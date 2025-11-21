# Firewood allocator telemetry

The nodestore allocator now exports per-area-size metrics for allocations, free-list splits, and
free-list depth. Names are shown as they appear in Prometheus after sanitization (`.` → `_`).

## Metric reference

- `firewood_allocations_from_end` (`index`)
  - Counter incremented whenever an allocation extends the nodestore (no free-list reuse).
- `firewood_allocations_reused` (`index`)
  - Counter incremented when an allocation is satisfied by a free-list entry of the given size.
- `firewood_allocations_reused_whole` (`area_size`)
  - Counter incremented when an allocation reuses an exact-size free-list entry (no split needed).
- `firewood_allocations_reused_split` (`area_size`)
  - Counter incremented when an allocation requires splitting a larger free-list entry.
- `firewood_freelist_split` (`from_index`, `target_index`)
  - Counter incremented every time a larger free area is split to satisfy a smaller request.
- `firewood_freelist_available` (`index`)
  - Gauge tracking the current number of cached free-list entries for each area size.

`index`/`from_index`/`target_index`/`area_size` use the human-readable area labels from
`index_name` (e.g. `16B`, `96B`, `4KB`). Combine these with the existing byte-based metrics
(`firewood_space_*`) to corroborate counts and volume.

## Example PromQL queries

- Allocations sourced from the free list in the last 15 minutes by area size:
  ```promql
  sum by (index)(increase(firewood_allocations_reused[15m]))
  ```
- Reuse mix (exact versus split) by area size:
  ```promql
  sum by (area_size)(increase(firewood_allocations_reused_whole[15m]))
  /
  sum by (area_size)(increase(firewood_allocations_reused_split[15m]))
  ```
- Allocations that grew the nodestore in the same window:
  ```promql
  sum by (index)(increase(firewood_allocations_from_end[15m]))
  ```
- Split pressure by target size:
  ```promql
  sum by (target_index)(increase(firewood_freelist_split[15m]))
  ```
- Current depth of each free list:
  ```promql
  firewood_freelist_available
  ```

## Sample Grafana panels

**Stacked allocation rate by source** (time series)

```json
{
  "title": "Nodestore allocations by source",
  "type": "timeseries",
  "stack": true,
  "targets": [
    {
      "expr": "sum by (index)(increase(firewood_allocations_reused[$__rate_interval]))",
      "legendFormat": "reuse {{index}}"
    },
    {
      "expr": "sum by (index)(increase(firewood_allocations_from_end[$__rate_interval]))",
      "legendFormat": "from_end {{index}}"
    }
  ]
}
```

**Reuse breakdown: split vs exact** (time series)

```json
{
  "title": "Free-list reuse breakdown",
  "type": "timeseries",
  "stack": true,
  "targets": [
    {
      "expr": "sum by (area_size)(increase(firewood_allocations_reused_whole[$__rate_interval]))",
      "legendFormat": "whole {{area_size}}"
    },
    {
      "expr": "sum by (area_size)(increase(firewood_allocations_reused_split[$__rate_interval]))",
      "legendFormat": "split {{area_size}}"
    }
  ]
}
```

**Free-list split hotspots** (table)

```json
{
  "title": "Free-list splits by target size",
  "type": "table",
  "transformations": [
    { "id": "labelsToFields" },
    { "id": "organize", "options": { "excludeByName": {}, "indexByName": {} } }
  ],
  "targets": [
    {
      "expr": "sum by (from_index, target_index)(increase(firewood_freelist_split[$__rate_interval]))",
      "legendFormat": "{{from_index}} → {{target_index}}"
    }
  ]
}
```

Import these snippets into an existing dashboard or use them as templates for bespoke panels that
combine allocation counts, byte volume, and free-list depth.
