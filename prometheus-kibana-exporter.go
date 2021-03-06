package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"strings"
	"os"
	"net/http"
	"encoding/json"
	"io"
	"io/ioutil"
	"sync"
	"net/url"
	"errors"
	"strconv"
	"time"
//    "gopkg.in/alecthomas/kingpin.v2"
//	"github.com/prometheus/common/log"
	log "github.com/sirupsen/logrus"
//	"github.com/sirupsen/logrus"
	"github.com/prometheus/common/version"
	"github.com/prometheus/client_golang/prometheus"
//	"github.com/prometheus/client_golang/prometheus/promhttp"
)
type Interface interface{}

////////////////////////////////////////////////////////////////////////////////
type KibanaServer struct {
	Name        string `json:"name"`
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number                           string    `json:"number"`
		BuildFlavor                      string    `json:"build_flavor"`
		BuildType                        string    `json:"build_type"`
		BuildHash                        string    `json:"build_hash"`
		BuildDate                        time.Time `json:"build_date"`
		BuildSnapshot                    bool      `json:"build_snapshot"`
		LuceneVersion                    string    `json:"lucene_version"`
		MinimumWireCompatibilityVersion  string    `json:"minimum_wire_compatibility_version"`
		MinimumIndexCompatibilityVersion string    `json:"minimum_index_compatibility_version"`
	} `json:"version"`
	Tagline string `json:"tagline"`
}
////////////////////////////////////////////////////////////////////////////////
type Sources struct {
    TimeFieldName string `json:"timeFieldName"`
    Title         string `json:"title"`
}
type AllHits struct {
    Index  string  `json:"_index"`
    Type   string  `json:"_type"`
    ID     string  `json:"_id"`
    Score  float64 `json:"_score"`
    Source Sources	`json:"_source"`
}
type KibanaIndexList struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total    int     `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []AllHits `json:"hits"`
	} `json:"hits"`
} 
/*type AllHits6 struct {
     Index  string `json:"_index"`
     Type   string `json:"_type"`
     ID     string `json:"_id"`
     Score  int    `json:"_score"`
     Source struct {
          IndexPattern Sources  `json:"index-pattern"`
          Type string `json:"type"`
     } `json:"_source"`
} 
type KibanaIndexList6 struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total    int `json:"total"`
		MaxScore int `json:"max_score"`
		Hits     []AllHits6 `json:"hits"`
	} `json:"hits"`
}*/
type KibanaIndexList6 struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total    int `json:"total"`
		MaxScore int `json:"max_score"`
		Hits     []struct {
			Index  string `json:"_index"`
			Type   string `json:"_type"`
			ID     string `json:"_id"`
			Score  int    `json:"_score"`
			Source struct {
				IndexPattern struct {
					TimeFieldName string `json:"timeFieldName"`
					Title         string `json:"title"`
				} `json:"index-pattern"`
				Type string `json:"type"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
////////////////////////////////////////////////////////////////////////////////

type SortHits struct {
    Index  string  `json:"_index"`
    Type   string  `json:"_type"`
    ID     string  `json:"_id"`
    Score  float64 `json:"_score"`
    Sort  []int64     `json:"sort"`
}
type KibanaIndexSort struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total    int         `json:"total"`
		MaxScore interface{} `json:"max_score"`
		Hits     []SortHits `json:"hits"`
	} `json:"hits"`
}
//////////////////////////////////////////////////////////////////////////////////
type KibanaIndixSize struct {
	Shards struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	All struct {
		Primaries struct {
			Docs struct {
				Count   int `json:"count"`
				Deleted int `json:"deleted"`
			} `json:"docs"`
			Store struct {
				SizeInBytes          int `json:"size_in_bytes"`
				ThrottleTimeInMillis int `json:"throttle_time_in_millis"`
			} `json:"store"`
			Indexing struct {
				IndexTotal           int  `json:"index_total"`
				IndexTimeInMillis    int  `json:"index_time_in_millis"`
				IndexCurrent         int  `json:"index_current"`
				IndexFailed          int  `json:"index_failed"`
				DeleteTotal          int  `json:"delete_total"`
				DeleteTimeInMillis   int  `json:"delete_time_in_millis"`
				DeleteCurrent        int  `json:"delete_current"`
				NoopUpdateTotal      int  `json:"noop_update_total"`
				IsThrottled          bool `json:"is_throttled"`
				ThrottleTimeInMillis int  `json:"throttle_time_in_millis"`
			} `json:"indexing"`
			Get struct {
				Total               int `json:"total"`
				TimeInMillis        int `json:"time_in_millis"`
				ExistsTotal         int `json:"exists_total"`
				ExistsTimeInMillis  int `json:"exists_time_in_millis"`
				MissingTotal        int `json:"missing_total"`
				MissingTimeInMillis int `json:"missing_time_in_millis"`
				Current             int `json:"current"`
			} `json:"get"`
			Search struct {
				OpenContexts        int `json:"open_contexts"`
				QueryTotal          int `json:"query_total"`
				QueryTimeInMillis   int `json:"query_time_in_millis"`
				QueryCurrent        int `json:"query_current"`
				FetchTotal          int `json:"fetch_total"`
				FetchTimeInMillis   int `json:"fetch_time_in_millis"`
				FetchCurrent        int `json:"fetch_current"`
				ScrollTotal         int `json:"scroll_total"`
				ScrollTimeInMillis  int `json:"scroll_time_in_millis"`
				ScrollCurrent       int `json:"scroll_current"`
				SuggestTotal        int `json:"suggest_total"`
				SuggestTimeInMillis int `json:"suggest_time_in_millis"`
				SuggestCurrent      int `json:"suggest_current"`
			} `json:"search"`
			Merges struct {
				Current                    int   `json:"current"`
				CurrentDocs                int   `json:"current_docs"`
				CurrentSizeInBytes         int   `json:"current_size_in_bytes"`
				Total                      int   `json:"total"`
				TotalTimeInMillis          int   `json:"total_time_in_millis"`
				TotalDocs                  int   `json:"total_docs"`
				TotalSizeInBytes           int `json:"total_size_in_bytes"`
				TotalStoppedTimeInMillis   int   `json:"total_stopped_time_in_millis"`
				TotalThrottledTimeInMillis int   `json:"total_throttled_time_in_millis"`
				TotalAutoThrottleInBytes   int `json:"total_auto_throttle_in_bytes"`
			} `json:"merges"`
			Refresh struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
				Listeners         int `json:"listeners"`
			} `json:"refresh"`
			Flush struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"flush"`
			Warmer struct {
				Current           int `json:"current"`
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"warmer"`
			QueryCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				TotalCount        int `json:"total_count"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
				CacheSize         int `json:"cache_size"`
				CacheCount        int `json:"cache_count"`
				Evictions         int `json:"evictions"`
			} `json:"query_cache"`
			Fielddata struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
			} `json:"fielddata"`
			Completion struct {
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"completion"`
			Segments struct {
				Count                     int `json:"count"`
				MemoryInBytes             int `json:"memory_in_bytes"`
				TermsMemoryInBytes        int `json:"terms_memory_in_bytes"`
				StoredFieldsMemoryInBytes int `json:"stored_fields_memory_in_bytes"`
				TermVectorsMemoryInBytes  int `json:"term_vectors_memory_in_bytes"`
				NormsMemoryInBytes        int `json:"norms_memory_in_bytes"`
				PointsMemoryInBytes       int `json:"points_memory_in_bytes"`
				DocValuesMemoryInBytes    int `json:"doc_values_memory_in_bytes"`
				IndexWriterMemoryInBytes  int `json:"index_writer_memory_in_bytes"`
				VersionMapMemoryInBytes   int `json:"version_map_memory_in_bytes"`
				FixedBitSetMemoryInBytes  int `json:"fixed_bit_set_memory_in_bytes"`
				MaxUnsafeAutoIDTimestamp  int `json:"max_unsafe_auto_id_timestamp"`
				FileSizes                 struct {
				} `json:"file_sizes"`
			} `json:"segments"`
			Translog struct {
				Operations  int `json:"operations"`
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"translog"`
			RequestCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
			} `json:"request_cache"`
			Recovery struct {
				CurrentAsSource      int `json:"current_as_source"`
				CurrentAsTarget      int `json:"current_as_target"`
				ThrottleTimeInMillis int `json:"throttle_time_in_millis"`
			} `json:"recovery"`
		} `json:"primaries"`
		Total struct {
			Docs struct {
				Count   int `json:"count"`
				Deleted int `json:"deleted"`
			} `json:"docs"`
			Store struct {
				SizeInBytes          int `json:"size_in_bytes"`
				ThrottleTimeInMillis int   `json:"throttle_time_in_millis"`
			} `json:"store"`
			Indexing struct {
				IndexTotal           int  `json:"index_total"`
				IndexTimeInMillis    int  `json:"index_time_in_millis"`
				IndexCurrent         int  `json:"index_current"`
				IndexFailed          int  `json:"index_failed"`
				DeleteTotal          int  `json:"delete_total"`
				DeleteTimeInMillis   int  `json:"delete_time_in_millis"`
				DeleteCurrent        int  `json:"delete_current"`
				NoopUpdateTotal      int  `json:"noop_update_total"`
				IsThrottled          bool `json:"is_throttled"`
				ThrottleTimeInMillis int  `json:"throttle_time_in_millis"`
			} `json:"indexing"`
			Get struct {
				Total               int `json:"total"`
				TimeInMillis        int `json:"time_in_millis"`
				ExistsTotal         int `json:"exists_total"`
				ExistsTimeInMillis  int `json:"exists_time_in_millis"`
				MissingTotal        int `json:"missing_total"`
				MissingTimeInMillis int `json:"missing_time_in_millis"`
				Current             int `json:"current"`
			} `json:"get"`
			Search struct {
				OpenContexts        int `json:"open_contexts"`
				QueryTotal          int `json:"query_total"`
				QueryTimeInMillis   int `json:"query_time_in_millis"`
				QueryCurrent        int `json:"query_current"`
				FetchTotal          int `json:"fetch_total"`
				FetchTimeInMillis   int `json:"fetch_time_in_millis"`
				FetchCurrent        int `json:"fetch_current"`
				ScrollTotal         int `json:"scroll_total"`
				ScrollTimeInMillis  int `json:"scroll_time_in_millis"`
				ScrollCurrent       int `json:"scroll_current"`
				SuggestTotal        int `json:"suggest_total"`
				SuggestTimeInMillis int `json:"suggest_time_in_millis"`
				SuggestCurrent      int `json:"suggest_current"`
			} `json:"search"`
			Merges struct {
				Current                    int   `json:"current"`
				CurrentDocs                int   `json:"current_docs"`
				CurrentSizeInBytes         int   `json:"current_size_in_bytes"`
				Total                      int   `json:"total"`
				TotalTimeInMillis          int   `json:"total_time_in_millis"`
				TotalDocs                  int   `json:"total_docs"`
				TotalSizeInBytes           int   `json:"total_size_in_bytes"`
				TotalStoppedTimeInMillis   int   `json:"total_stopped_time_in_millis"`
				TotalThrottledTimeInMillis int   `json:"total_throttled_time_in_millis"`
				TotalAutoThrottleInBytes   int   `json:"total_auto_throttle_in_bytes"`
			} `json:"merges"`
			Refresh struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
				Listeners         int `json:"listeners"`
			} `json:"refresh"`
			Flush struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"flush"`
			Warmer struct {
				Current           int `json:"current"`
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"warmer"`
			QueryCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				TotalCount        int `json:"total_count"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
				CacheSize         int `json:"cache_size"`
				CacheCount        int `json:"cache_count"`
				Evictions         int `json:"evictions"`
			} `json:"query_cache"`
			Fielddata struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
			} `json:"fielddata"`
			Completion struct {
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"completion"`
			Segments struct {
				Count                     int `json:"count"`
				MemoryInBytes             int `json:"memory_in_bytes"`
				TermsMemoryInBytes        int `json:"terms_memory_in_bytes"`
				StoredFieldsMemoryInBytes int `json:"stored_fields_memory_in_bytes"`
				TermVectorsMemoryInBytes  int `json:"term_vectors_memory_in_bytes"`
				NormsMemoryInBytes        int `json:"norms_memory_in_bytes"`
				PointsMemoryInBytes       int `json:"points_memory_in_bytes"`
				DocValuesMemoryInBytes    int `json:"doc_values_memory_in_bytes"`
				IndexWriterMemoryInBytes  int `json:"index_writer_memory_in_bytes"`
				VersionMapMemoryInBytes   int `json:"version_map_memory_in_bytes"`
				FixedBitSetMemoryInBytes  int `json:"fixed_bit_set_memory_in_bytes"`
				MaxUnsafeAutoIDTimestamp  int `json:"max_unsafe_auto_id_timestamp"`
				FileSizes                 struct {
				} `json:"file_sizes"`
			} `json:"segments"`
			Translog struct {
				Operations  int `json:"operations"`
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"translog"`
			RequestCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
			} `json:"request_cache"`
			Recovery struct {
				CurrentAsSource      int `json:"current_as_source"`
				CurrentAsTarget      int `json:"current_as_target"`
				ThrottleTimeInMillis int `json:"throttle_time_in_millis"`
			} `json:"recovery"`
		} `json:"total"`
	} `json:"_all"`
	
}

type KibanaIndixSize6 struct {
	Shards struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	All struct {
		Primaries struct {
			Docs struct {
				Count   int `json:"count"`
				Deleted int `json:"deleted"`
			} `json:"docs"`
			Store struct {
				SizeInBytes          int64 `json:"size_in_bytes"`
				
			} `json:"store"`
			Indexing struct {
				IndexTotal           int  `json:"index_total"`
				IndexTimeInMillis    int  `json:"index_time_in_millis"`
				IndexCurrent         int  `json:"index_current"`
				IndexFailed          int  `json:"index_failed"`
				DeleteTotal          int  `json:"delete_total"`
				DeleteTimeInMillis   int  `json:"delete_time_in_millis"`
				DeleteCurrent        int  `json:"delete_current"`
				NoopUpdateTotal      int  `json:"noop_update_total"`
				IsThrottled          bool `json:"is_throttled"`
				ThrottleTimeInMillis int  `json:"throttle_time_in_millis"`
			} `json:"indexing"`
			Get struct {
				Total               int `json:"total"`
				TimeInMillis        int `json:"time_in_millis"`
				ExistsTotal         int `json:"exists_total"`
				ExistsTimeInMillis  int `json:"exists_time_in_millis"`
				MissingTotal        int `json:"missing_total"`
				MissingTimeInMillis int `json:"missing_time_in_millis"`
				Current             int `json:"current"`
			} `json:"get"`
			Search struct {
				OpenContexts        int `json:"open_contexts"`
				QueryTotal          int `json:"query_total"`
				QueryTimeInMillis   int `json:"query_time_in_millis"`
				QueryCurrent        int `json:"query_current"`
				FetchTotal          int `json:"fetch_total"`
				FetchTimeInMillis   int `json:"fetch_time_in_millis"`
				FetchCurrent        int `json:"fetch_current"`
				ScrollTotal         int `json:"scroll_total"`
				ScrollTimeInMillis  int `json:"scroll_time_in_millis"`
				ScrollCurrent       int `json:"scroll_current"`
				SuggestTotal        int `json:"suggest_total"`
				SuggestTimeInMillis int `json:"suggest_time_in_millis"`
				SuggestCurrent      int `json:"suggest_current"`
			} `json:"search"`
			Merges struct {
				Current                    int   `json:"current"`
				CurrentDocs                int   `json:"current_docs"`
				CurrentSizeInBytes         int   `json:"current_size_in_bytes"`
				Total                      int   `json:"total"`
				TotalTimeInMillis          int   `json:"total_time_in_millis"`
				TotalDocs                  int   `json:"total_docs"`
				TotalSizeInBytes           int `json:"total_size_in_bytes"`
				TotalStoppedTimeInMillis   int   `json:"total_stopped_time_in_millis"`
				TotalThrottledTimeInMillis int   `json:"total_throttled_time_in_millis"`
				TotalAutoThrottleInBytes   int `json:"total_auto_throttle_in_bytes"`
			} `json:"merges"`
			Refresh struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
				Listeners         int `json:"listeners"`
			} `json:"refresh"`
			Flush struct {
				Total             int `json:"total"`
				Periodic          int `json:"periodic"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"flush"`
			Warmer struct {
				Current           int `json:"current"`
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"warmer"`
			QueryCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				TotalCount        int `json:"total_count"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
				CacheSize         int `json:"cache_size"`
				CacheCount        int `json:"cache_count"`
				Evictions         int `json:"evictions"`
			} `json:"query_cache"`
			Fielddata struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
			} `json:"fielddata"`
			Completion struct {
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"completion"`
			Segments struct {
				Count                     int `json:"count"`
				MemoryInBytes             int `json:"memory_in_bytes"`
				TermsMemoryInBytes        int `json:"terms_memory_in_bytes"`
				StoredFieldsMemoryInBytes int `json:"stored_fields_memory_in_bytes"`
				TermVectorsMemoryInBytes  int `json:"term_vectors_memory_in_bytes"`
				NormsMemoryInBytes        int `json:"norms_memory_in_bytes"`
				PointsMemoryInBytes       int `json:"points_memory_in_bytes"`
				DocValuesMemoryInBytes    int `json:"doc_values_memory_in_bytes"`
				IndexWriterMemoryInBytes  int `json:"index_writer_memory_in_bytes"`
				VersionMapMemoryInBytes   int `json:"version_map_memory_in_bytes"`
				FixedBitSetMemoryInBytes  int `json:"fixed_bit_set_memory_in_bytes"`
				MaxUnsafeAutoIDTimestamp  int64 `json:"max_unsafe_auto_id_timestamp"`
				FileSizes                 struct {
				} `json:"file_sizes"`
			} `json:"segments"`
			Translog struct {
				Operations  int `json:"operations"`
				SizeInBytes int `json:"size_in_bytes"`
				UncommittedOperations   int `json:"uncommitted_operations"`
				UncommittedSizeInBytes  int `json:"uncommitted_size_in_bytes"`
				EarliestLastModifiedAge int `json:"earliest_last_modified_age"`
			} `json:"translog"`
			RequestCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
			} `json:"request_cache"`
			Recovery struct {
				CurrentAsSource      int `json:"current_as_source"`
				CurrentAsTarget      int `json:"current_as_target"`
				ThrottleTimeInMillis int `json:"throttle_time_in_millis"`
			} `json:"recovery"`
		} `json:"primaries"`
		Total struct {
			Docs struct {
				Count   int `json:"count"`
				Deleted int `json:"deleted"`
			} `json:"docs"`
			Store struct {
				SizeInBytes          int `json:"size_in_bytes"`
				
			} `json:"store"`
			Indexing struct {
				IndexTotal           int  `json:"index_total"`
				IndexTimeInMillis    int  `json:"index_time_in_millis"`
				IndexCurrent         int  `json:"index_current"`
				IndexFailed          int  `json:"index_failed"`
				DeleteTotal          int  `json:"delete_total"`
				DeleteTimeInMillis   int  `json:"delete_time_in_millis"`
				DeleteCurrent        int  `json:"delete_current"`
				NoopUpdateTotal      int  `json:"noop_update_total"`
				IsThrottled          bool `json:"is_throttled"`
				ThrottleTimeInMillis int  `json:"throttle_time_in_millis"`
			} `json:"indexing"`
			Get struct {
				Total               int `json:"total"`
				TimeInMillis        int `json:"time_in_millis"`
				ExistsTotal         int `json:"exists_total"`
				ExistsTimeInMillis  int `json:"exists_time_in_millis"`
				MissingTotal        int `json:"missing_total"`
				MissingTimeInMillis int `json:"missing_time_in_millis"`
				Current             int `json:"current"`
			} `json:"get"`
			Search struct {
				OpenContexts        int `json:"open_contexts"`
				QueryTotal          int `json:"query_total"`
				QueryTimeInMillis   int `json:"query_time_in_millis"`
				QueryCurrent        int `json:"query_current"`
				FetchTotal          int `json:"fetch_total"`
				FetchTimeInMillis   int `json:"fetch_time_in_millis"`
				FetchCurrent        int `json:"fetch_current"`
				ScrollTotal         int `json:"scroll_total"`
				ScrollTimeInMillis  int `json:"scroll_time_in_millis"`
				ScrollCurrent       int `json:"scroll_current"`
				SuggestTotal        int `json:"suggest_total"`
				SuggestTimeInMillis int `json:"suggest_time_in_millis"`
				SuggestCurrent      int `json:"suggest_current"`
			} `json:"search"`
			Merges struct {
				Current                    int   `json:"current"`
				CurrentDocs                int   `json:"current_docs"`
				CurrentSizeInBytes         int   `json:"current_size_in_bytes"`
				Total                      int   `json:"total"`
				TotalTimeInMillis          int   `json:"total_time_in_millis"`
				TotalDocs                  int   `json:"total_docs"`
				TotalSizeInBytes           int   `json:"total_size_in_bytes"`
				TotalStoppedTimeInMillis   int   `json:"total_stopped_time_in_millis"`
				TotalThrottledTimeInMillis int   `json:"total_throttled_time_in_millis"`
				TotalAutoThrottleInBytes   int   `json:"total_auto_throttle_in_bytes"`
			} `json:"merges"`
			Refresh struct {
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
				Listeners         int `json:"listeners"`
			} `json:"refresh"`
			Flush struct {
				Total             int `json:"total"`
				Periodic          int `json:"periodic"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"flush"`
			Warmer struct {
				Current           int `json:"current"`
				Total             int `json:"total"`
				TotalTimeInMillis int `json:"total_time_in_millis"`
			} `json:"warmer"`
			QueryCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				TotalCount        int `json:"total_count"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
				CacheSize         int `json:"cache_size"`
				CacheCount        int `json:"cache_count"`
				Evictions         int `json:"evictions"`
			} `json:"query_cache"`
			Fielddata struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
			} `json:"fielddata"`
			Completion struct {
				SizeInBytes int `json:"size_in_bytes"`
			} `json:"completion"`
			Segments struct {
				Count                     int `json:"count"`
				MemoryInBytes             int `json:"memory_in_bytes"`
				TermsMemoryInBytes        int `json:"terms_memory_in_bytes"`
				StoredFieldsMemoryInBytes int `json:"stored_fields_memory_in_bytes"`
				TermVectorsMemoryInBytes  int `json:"term_vectors_memory_in_bytes"`
				NormsMemoryInBytes        int `json:"norms_memory_in_bytes"`
				PointsMemoryInBytes       int `json:"points_memory_in_bytes"`
				DocValuesMemoryInBytes    int `json:"doc_values_memory_in_bytes"`
				IndexWriterMemoryInBytes  int `json:"index_writer_memory_in_bytes"`
				VersionMapMemoryInBytes   int `json:"version_map_memory_in_bytes"`
				FixedBitSetMemoryInBytes  int `json:"fixed_bit_set_memory_in_bytes"`
				MaxUnsafeAutoIDTimestamp  int64 `json:"max_unsafe_auto_id_timestamp"`
				FileSizes                 struct {
				} `json:"file_sizes"`
			} `json:"segments"`
			Translog struct {
				Operations  int `json:"operations"`
				SizeInBytes int `json:"size_in_bytes"`
				UncommittedOperations   int `json:"uncommitted_operations"`
				UncommittedSizeInBytes  int `json:"uncommitted_size_in_bytes"`
				EarliestLastModifiedAge int `json:"earliest_last_modified_age"`
			} `json:"translog"`
			RequestCache struct {
				MemorySizeInBytes int `json:"memory_size_in_bytes"`
				Evictions         int `json:"evictions"`
				HitCount          int `json:"hit_count"`
				MissCount         int `json:"miss_count"`
			} `json:"request_cache"`
			Recovery struct {
				CurrentAsSource      int `json:"current_as_source"`
				CurrentAsTarget      int `json:"current_as_target"`
				ThrottleTimeInMillis int `json:"throttle_time_in_millis"`
			} `json:"recovery"`
		} `json:"total"`
	} `json:"_all"`
	
}

//////////////////////////////////////////////////////////////////////////////////

type Exporter struct {
	URI   string
	mutex sync.RWMutex
	fetch func() (io.ReadCloser, error)

	up                                             prometheus.Gauge
//	kibanaIndexLatestTime								   prometheus.CounterVec 

}
var (
	kibanaIndexLatestTime= prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kibana_index_latest_data_time",
				Help: "kibana index latest data time .",
			},		
			[]string{"indexpattern"},
		)
	kibanaIndexOldestTime= prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kibana_index_oldest_data_time",
				Help: "kibana index Oldest data time .",
			},		
			[]string{"indexpattern"},
		)
	kibanaIndexSize = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kibana_index_size_total",
				Help: "kibana index size total.",
			},		
			[]string{"indexpattern"},
		)
)
type Indexpattern struct {
    timeFieldName string `json:"_source.timeFieldName"`
    title string `json:"_source.title"`
}
/*
func NewNodeStatsCollector(logstashEndpoint string) (Collector, error) {
	const subsystem = "node"

	return &NodeStatsCollector{

		PipelinePluginEventsDuration: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "plugin_duration_seconds_total"),
			"plugin_duration_seconds",
			[]string{"pipeline", "plugin", "plugin_id", "plugin_type"},
			nil,
		),
	}, nil
}
*/
func NewExporter(uri string) (*Exporter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var fetch func() (io.ReadCloser, error)
	switch u.Scheme {
	case "http", "https":
		fetch = fetchHTTP(uri)
	default:
		return nil, fmt.Errorf("unsupported scheme: %q", u.Scheme)
	}

	return &Exporter{
		URI:   uri,
		fetch: fetch,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      "up",
			Help:      "Was the last scrape of haproxy successful.",
		}),
		
	}, nil
}

func fetchHTTP(uri string) func() (io.ReadCloser, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := http.Client{
		Timeout:   50,
		Transport: tr,
	}

	return func() (io.ReadCloser, error) {
		resp, err := client.Get(uri)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
/*	for _, m := range e.frontendMetrics {
		m.Describe(ch)
	}
	for _, m := range e.backendMetrics {
		m.Describe(ch)
	}
	for _, m := range e.serverMetrics {
		m.Describe(ch)
	}
*/	//ch <- kibanaIndexLatestTime.Metric()
	ch <- e.up.Desc()
}

func getObject(path string,body io.Reader,StructInterface interface{}) error {
	req, err := http.NewRequest("GET",  path, body)
	if err != nil {
		log.Error(err)
		return err
		// handle err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(err)
		return  err
		// handle err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
	    responsebody, err := ioutil.ReadAll(resp.Body)
	    if err != nil {
			log.Error(err)
			return  err
		}
//	    log.Error(string(responsebody))
	    
		err2 := json.Unmarshal(responsebody,&StructInterface)
	    if err2 != nil {
			log.Error(err2)
			return  err
		}
		return nil
	}else {
//		log.Error("Please check url")
		return errors.New("Please check url "+ strconv.FormatInt(int64(resp.StatusCode), 10) )
	}
}
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()

//	e.resetMetrics()
//	e.scrape()

//      Check version
	urlPath := "/"
	ESversion := "5.6"
        body := strings.NewReader(``)
        var StructServerObject KibanaServer
        var InterfaceServerObject *Interface
        InterfaceServerObject = new(Interface)
        *InterfaceServerObject = &StructServerObject

        errS := getObject( e.URI + urlPath,body,&InterfaceServerObject)
        if errS != nil {
                log.Error(errS)
                return
        }
    if StructServerObject.Version.Number > "6.3.0"{
    	ESversion = "6.3"
    }
    if StructServerObject.Version.Number > "6.1.0"{
        ESversion = "6.3"
    }
    if StructServerObject.Version.Number > "6.0.0"{
        ESversion = "6.3"
    }

    log.Debug(StructServerObject.Version.Number)
 //     Get Index List
    urlPath = "/.kibana/_search?size=1000"
	if ESversion == "6.3" {
//		body = strings.NewReader(`{   "_source" : {       "includes": [ "index-pattern.timeFieldName","index-pattern.title",  "type" ]     }}`)
		body = strings.NewReader(`{
  "query": { 
    "bool": { 
      "filter": [
        { "term": { "type":   "index-pattern"        }} 
          
      ]
    }
  },
   "_source" : {       "includes": [  "index-pattern.title", "index-pattern.timeFieldName","type" ]     }}`)
		log.Info("Detected 6.3.0 version while index search")
	}else{
		body = strings.NewReader(`{   "_source": {         "includes": [ "title", "timeFieldName" ]     } }`)
	}
	
	
	var StructInterfaceObject KibanaIndexList
	var StructInterfaceObject6 KibanaIndexList6
	
	var InterfaceObject *Interface
	InterfaceObject = new(Interface)

    
	if ESversion == "6.3" {
		*InterfaceObject = &StructInterfaceObject6
	}else{
		*InterfaceObject = &StructInterfaceObject
	}

	err := getObject( e.URI + urlPath,body,&InterfaceObject)
	if err != nil {
		log.Error(err)
		return
	}

	var SourceIndexes []Sources

	if ESversion == "6.3"{
		for _, i := range StructInterfaceObject6.Hits.Hits {
			log.Info(i.Source.IndexPattern.Title + " " + i.Source.Type +" " +i.Source.IndexPattern.TimeFieldName )
			if i.Source.Type == "index-pattern"{
				var tempSource Sources
				tempSource.Title = i.Source.IndexPattern.Title
				tempSource.TimeFieldName = i.Source.IndexPattern.TimeFieldName
				SourceIndexes = append(SourceIndexes,tempSource)
			}
		}
	}else{
		for _, i := range StructInterfaceObject.Hits.Hits {
			log.Info(i.Source.Title + " " + i.Type +" " +i.Source.TimeFieldName )
			if i.Type == "index-pattern"{
				var tempSource Sources
				tempSource.Title = i.Source.Title
				tempSource.TimeFieldName = i.Source.TimeFieldName
				SourceIndexes = append(SourceIndexes,tempSource)
			}
		}
	}
		for _, i := range SourceIndexes {
			// Latest time 
			urlPath := "/"+i.Title+ "/_search"
			body := strings.NewReader(`{ "_source": false, "sort": [{ "`+i.TimeFieldName+`": { "order": "desc" } } ], "size": 1 }`)

			var StructInterfaceSortObject KibanaIndexSort
			var InterfaceSortObject *Interface
			InterfaceSortObject = new(Interface)
			*InterfaceSortObject = &StructInterfaceSortObject
				err := getObject( e.URI + urlPath,body,&InterfaceSortObject)
				if err != nil {
					log.Error(err)
//									log.Info(i.Title +" - 0")
									kibanaIndexLatestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(0)		
				}else{
					if len(StructInterfaceSortObject.Hits.Hits) >0 {
//									log.Info(i.Title +" - " +strconv.FormatInt(int64(StructInterfaceSortObject.Hits.Hits[0].Sort[0]),10))		
									kibanaIndexLatestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(float64(StructInterfaceSortObject.Hits.Hits[0].Sort[0]))
					}else{
//									log.Info(i.Title +" - 0")	
									kibanaIndexLatestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(0)	
					}
				}
			// Oldest time 
			urlPath = "/"+i.Title+ "/_search"
			body = strings.NewReader(`{ "_source": false, "sort": [{ "`+i.TimeFieldName+`": { "order": "asc" } } ], "size": 1 }`)

			var StructInterfaceSortAscObject KibanaIndexSort
			var InterfaceSortAscObject *Interface
			InterfaceSortAscObject = new(Interface)
			*InterfaceSortAscObject = &StructInterfaceSortAscObject
				err9 := getObject( e.URI + urlPath,body,&InterfaceSortAscObject)
				if err9 != nil {
					log.Error(err9)
									log.Debug(i.Title +" - 0")
									kibanaIndexOldestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(0)		
				}else{
					if len(StructInterfaceSortAscObject.Hits.Hits) >0 {
									log.Debug(i.Title +" - " +strconv.FormatInt(int64(StructInterfaceSortAscObject.Hits.Hits[0].Sort[0]),10))		
									kibanaIndexOldestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(float64(StructInterfaceSortAscObject.Hits.Hits[0].Sort[0]))
					}else{
									log.Debug(i.Title +" - 0")	
									kibanaIndexOldestTime.With(prometheus.Labels{"indexpattern":i.Title}).Set(0)	
					}
				}
			// Size Index 
			urlPath = "/"+i.Title+ "/_stats"
			body = strings.NewReader(``)

			var StructInterfaceSizeObject KibanaIndixSize
			var StructInterfaceSizeObject6 KibanaIndixSize6

			var InterfaceSizeObject *Interface
			InterfaceSizeObject = new(Interface)

				if ESversion == "6.3" {
					*InterfaceSizeObject = &StructInterfaceSizeObject6
				}else{
					*InterfaceSizeObject = &StructInterfaceSizeObject
				}

				err99 := getObject( e.URI + urlPath,body,&InterfaceSizeObject)
				if err99 != nil {
					log.Error(err99)
//									log.Info(i.Title +" - 0")
									kibanaIndexSize.With(prometheus.Labels{"indexpattern":i.Title}).Set(0)		
				}else{
//					if len(StructInterfaceSizeObject.All.Total.Store.SizeInBytes) >0 {
//									log.Info(i.Title +" - " +strconv.FormatInt(int64(StructInterfaceSizeObject.All.Total.Store.SizeInBytes),10))		

						if ESversion == "6.3" {
									kibanaIndexSize.With(prometheus.Labels{"indexpattern":i.Title}).Set(float64(StructInterfaceSizeObject6.All.Total.Store.SizeInBytes))
						}else{
									kibanaIndexSize.With(prometheus.Labels{"indexpattern":i.Title}).Set(float64(StructInterfaceSizeObject.All.Total.Store.SizeInBytes))
						}

//					}else{
//									log.Info(i.Title +" - 0")	
//									kibanaIndexSize.With(prometheus.Labels{"indexpattern":i.Title}).Add(0)	
//					}
				}				
		}
		

	ch <- e.up
//	e.collectMetrics(ch)
}
/*var (
	cpuChk = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_temperature_celsius",
		Help: "Current temperature of the CPU.",
	}) 
	hdFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hd_errors_total",
			Help: "Number of hard-disk errors.",
		},
		[]string{"device"},
	)
)*/

func init() {
	// Metrics have to be registered to be exposed:
//	prometheus.MustRegister(cpuChk)
//	prometheus.MustRegister(hdFailures)
	prometheus.MustRegister(kibanaIndexLatestTime)
	prometheus.MustRegister(kibanaIndexOldestTime)
	prometheus.MustRegister(kibanaIndexSize)
}

func main() {
	var (
				Name                 = "Kibana_Index_exporter"
				listenAddress        = flag.String("web.listen-address", ":9108", "Address to listen on for web interface and telemetry.")
				metricsPath          = flag.String("web.telemetry-path","/metrics", "Path under which to expose metrics.")
				showVersion          = flag.Bool("version", false, "Show version and exit")
				esURI                = flag.String("es.uri", "http://localhost:9200", "HTTP API address of an Elasticsearch node.")
				loglevel			 = flag.Bool("debug",false,"Set up loglevel in debug")
	)

//	cpuChk.Set(65.3)
	flag.Parse()
//	origLogger.SetLevel(origLogger.DebugLevel)
//	log := logrus.new()
	fmt.Print("Listening to:" + *esURI +"\n")
	fmt.Print("Add http://localhost"+ *listenAddress + *metricsPath +"\n")

	if *showVersion {
		fmt.Print(version.Print(Name))
		os.Exit(0)
	}
//	hdFailures.With(prometheus.Labels{"device":"/dev/sda"}).Inc()
//	log.SetLevel("debug")
//	k := kingpin.New(*loglevel,"debug")
	log.SetLevel(log.WarnLevel)
	if *loglevel{
		log.SetLevel(log.DebugLevel)
	}
	
//	log.AddFlags(k)
	exporter, err := NewExporter(*esURI)
	if err != nil {
		log.Fatal(err)
	}
	prometheus.MustRegister(exporter)


	// The Handler function provides a default handler to expose metrics
	// via an HTTP server. "/metrics" is the usual endpoint for that.
	// https://hk.saowen.com/a/82669ec3819451029c535e7a1ad6ad2a3121ad864dc9f3fb1eb2bc6602554b44
	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Kibana Index Exporter</title></head>
             <body>
             <h1>Kibana Index Exporter</h1>
             <p><a href='`+ *metricsPath +`'>Metrics</a></p>
             </body>
             </html>`))
	})
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Error(
			"msg", "http server quit",
			"err", err,
		)
	}

}
