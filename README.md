# Josh_Test - Splunk Detection Content Pack

Custom Splunk detection content pack with a CI/CD pipeline. Write detections as `.conf` files, push to `main`, and a versioned app `.tgz` is automatically built.

---

## Directory Structure

```
detections/          <- saved search .conf or .yml files (one per detection)
macros/              <- macro .conf files (or define inline in YAML detections)
lookups/             <- lookup CSV files
dashboards/          <- dashboard XML files
app_template/        <- static app files (metadata, icons, nav, views)
app_build.yml        <- app metadata (name, version, author)
build.py             <- build script (assembles the app)
.github/workflows/   <- GitHub Actions workflow
```

---

## Adding a Detection

There are two ways to add detections: directly as Splunk `.conf` files, or as structured `.yml` files that get converted at build time. Both file types can coexist in `detections/` and are merged into a single `savedsearches.conf`.

### Option 1: Splunk .conf File (Direct)

Create a `.conf` file in `detections/` (e.g. `my_detection.conf`) with a standard Splunk saved search stanza:

```ini
[My Detection Name]
search = index=main sourcetype=foo | stats count by dest
cron_schedule = 0 * * * *
dispatch.earliest_time = -70m@m
dispatch.latest_time = -10m@m
action.risk = 1
action.risk.param._risk = [{"risk_object_field": "dest", "risk_object_type": "system", "risk_score": 60}]
action.risk.param._risk_message = Something happened on $dest$
enableSched = 1
alert.track = 1
```

This is a direct pass-through -- the stanza is included in the built app exactly as written.

### Option 2: YAML Detection File

Create a `.yml` file in `detections/` (e.g. `my_detection.yml`). The build script converts it into the corresponding `savedsearches.conf` stanza automatically, including correlation search, notable, RBA, and drilldown configuration.

```yaml
name: My Detection Name
description:
  - Detects suspicious activity on dest
search: 'index=main sourcetype=foo | stats count by dest'
type: ebd
enabled_by_default: false

scheduling:
  cron_schedule: '0 * * * *'
  earliest_time: '-70m@m'
  latest_time: '-10m@m'
  schedule_window: auto

alert_action:
  notable:
    enabled: true
    rule_title: '%name%'
    rule_description: '%description%'
    severity: high
    field: user
    type: user
    score: 0
    domain: threat                # one of: access endpoint network threat identity audit

rba:
  enabled: true
  message:
    - An instance of $process_name$ was detected on $dest$ by $user$.
  risk_objects:
    - field: user
      type: user
      score: 56
    - field: dest
      type: system
      score: 60
  threat_objects:
    - field: process_name
      type: process_name

drilldown_searches:
  - name: View the detection results for $user$ and $dest$
    search: '%original_detection_search% | search user = $user$ dest = $dest$'
    earliest_offset: $info_min_time$
    latest_offset: $info_max_time$

annotations:
  cve:
    - CVE-2024-12345
  mitre_attack:
    - T1059.001
  status:
    - production

macros:
  - name: my_macro
    definition: search index=main
    description: filters to main index
  - name: my_macro_with_arg(1)
    definition: search index=main $field$
    description: filters with a field argument
    arguments:
      - field
```

Template variables `%name%`, `%description%`, and `%original_detection_search%` are resolved automatically in fields like `rule_title`, `rule_description`, and drilldown searches.

The stanza name is auto-generated as `Domain - Name - Rule` (e.g. `Threat - My Detection Name - Rule`).

---

## Adding a Macro

There are two ways to add macros:

### Option 1: Splunk .conf File (Direct)

Create a `.conf` file in `macros/`:

```ini
[my_macro(1)]
definition = where $field$!=""
args = field
```

All macro `.conf` files in `macros/` get concatenated into `macros.conf`.

### Option 2: Inline in a YAML Detection

Add a `macros:` section to any `.yml` detection file in `detections/`:

```yaml
macros:
  - name: my_macro
    definition: search index=main
    description: filters to main index

  - name: my_macro_with_arg
    definition: search index=main $field$
    description: filters with a field argument
    arguments:
      - field
```

Macros defined in YAML files are extracted at build time and merged with any `.conf` macros into a single `macros.conf`.

---

## Adding Lookups

Drop `.csv` files into `lookups/`. They get copied into the app's `lookups/` directory at build time.

---

## Adding Dashboards

1. Create a `.xml` dashboard file in `dashboards/`
2. Make it visible in the app -- two options:
   - **Prefix the filename with `__`** (e.g. `__my_dashboard.xml`) -- it auto-discovers into the Dashboards nav collection
   - **Explicitly add it to the nav** in `app_template/default/data/ui/nav/default.xml`:
     ```xml
     <collection label="Dashboards">
       <view name="my_dashboard"/>   <!-- add this line -->
       <view source="unclassified" match="__"/>
     </collection>
     ```
3. Push to `main`

The build copies all `.xml` files from `dashboards/` into `default/data/ui/views/` automatically. The nav step is what controls whether it actually shows up in the app.

---

## Versioning

Version format: `major.minor.patch`

- **Major.minor** -- set manually in `app_build.yml`
- **Patch** -- auto-increments based on git commit count (no action needed)

Example: if `app_build.yml` has `version: "0.0"` and you have 12 commits, the built app is `0.0.12`.

### Bumping Major or Minor

Edit `app_build.yml` and change the version:

```yaml
app:
  version: "0.1"   # was "0.0", now minor bumped to 1
```

Push to `main`. Patch resets relative to the new base (it's still the commit count, but the minor change is what matters).

---

## CI/CD Pipeline

- Push to `main` triggers the GitHub Action
- The action runs `build.py`, which assembles the Splunk app
- A versioned artifact is uploaded (e.g. `Josh_Test_0.0.12`)
- The artifact contains the `.tgz` (deploy this) and the extracted app directory (inspect this)

### What Triggers a Build

Only changes to these paths trigger the workflow:

- `detections/`
- `macros/`
- `lookups/`
- `dashboards/`
- `app_template/`
- `app_build.yml`

Changes to `README.md`, `build.py`, or `.github/` do **not** trigger a build.

---

## App Metadata

Edit `app_build.yml` to change app-level settings:

```yaml
app:
  uid: 37057
  title: Josh_Test        # app title
  appid: Josh_Test        # app ID (folder name inside .tgz -- don't change after first deploy)
  version: "0.0"          # major.minor only, patch is automatic
  description: This is an app
  author_name: Josh
  author_email: Josh
  author_company: author company
```
