# prometheus-kibana-exporter
Prometheus Kibana Exporter
# Build & Execute
```
git clone https://github.com/niravshah2705/prometheus-kibana-exporter.git
go build prometheus-kibana-exporter.go
./prometheus-kibana-exporter &>prometheus-kibana-exporter.log &
```

# Parameter
./prometheus-kibana-exporter --help

|parameter|usage|
|---|---|
|-es.uri |HTTP API address of an Elasticsearch node. (default "http://localhost:9200") |
|-version | Show version and exit |
|-web.listen-address | Address to listen on for web interface and telemetry. (default ":9108")|
|-web.telemetry-path | Path under which to expose metrics. (default "/metrics") |

# Prometheus configuration
The prometheus endpoint is resource consuming. Thus use longer scrape interval. 
```
- job_name: kibana_exporter
  honor_labels: true
  scrape_interval: 2m
  scrape_timeout: 50s
  metrics_path: /metrics
  scheme: http
  static_configs:
  - targets:
    - xxx.xxx.xxx.xxx:9108
    labels:
      env: prod
      service: kibana
      stack: elasticsearch
      type: service
```
# Metrics
Unlike other elasticsearch exporter, this exporter does not capture per indices details. Rather it is capturing details of kibana index pattern, that is end user specific. Usually we get request that if my index does not recieve data from 15 minutes that's alarming scenario, we can perform that using this exporter.

The metrics collection done as below:

|Metric|usage|
|---|---|
|kibana_index_latest_data_time| For each index pattern, latest epoch time pushed for time filter field | 
|kibana_index_oldest_data_time| For each index pattern, oldest epoch time pushed for time filter field,to check archiving  |
|kibana_index_size_total| For each index pattern, Size consumed in bytes total (including replication factor) |

# Sample Metrics logs
```
# HELP kibana_index_latest_data_time kibana index latest data time .
# TYPE kibana_index_latest_data_time gauge
kibana_index_latest_data_time{indexpattern="app1-access-*"} 1.525649970606e+12
kibana_index_latest_data_time{indexpattern="app2-access-*"} 1.525649924426e+12
kibana_index_latest_data_time{indexpattern="app1-application-*"} 1.525649971964e+12
# HELP kibana_index_oldest_data_time kibana index Oldest data time .
# TYPE kibana_index_oldest_data_time gauge
kibana_index_oldest_data_time{indexpattern="app1-access-*"} 1.524125316836e+12
kibana_index_oldest_data_time{indexpattern="app2-access-*"} 1.524211761915e+12
kibana_index_oldest_data_time{indexpattern="app1-application-*"} 1.52411343669e+12
# HELP kibana_index_size_total kibana index size total.
# TYPE kibana_index_size_total gauge
kibana_index_size_total{indexpattern="app1-access-*"} 4.174622357e+09
kibana_index_size_total{indexpattern="app2-access-*"} 3.353926281e+09
kibana_index_size_total{indexpattern="app1-application-*"} 5.18314035e+09
```
# Alerts

|Alert|duration|prometheus expression|
|---|---|---|
|IndexLag | >15 mins | `(time()*1000 - kibana_index_latest_data_time ) /1000/60 > 15 and kibana_index_latest_data_time != 0`|
