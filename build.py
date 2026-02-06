"""
Splunk app build script.

Assembles detections, macros, and app_template into a packaged .tgz app.
Output goes to dist/:
  dist/Josh_Test_0.0.3/      <- assembled app (inspect this)
  dist/Josh_Test_0.0.3.tgz   <- packaged app (deploy this)

Version: major.minor from app_build.yml, patch from git commit count.
"""
import os
import glob
import shutil
import tarfile
import subprocess
import json
import yaml

APP_BUILD_YML   = "app_build.yml"
APP_TEMPLATE    = "app_template"
DETECTIONS_DIR  = "detections"
MACROS_DIR      = "macros"
LOOKUPS_DIR     = "lookups"
DASHBOARDS_DIR  = "dashboards"
DIST_DIR        = "dist"


def get_patch_version():
    """Get patch number from git commit count, or 0 if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, check=True
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 0


def get_version(app):
    """Build full version: major.minor from contentctl.yml, patch from git."""
    base = str(app.get("version", "0.0"))
    parts = base.split(".")
    major = parts[0] if len(parts) > 0 else "0"
    minor = parts[1] if len(parts) > 1 else "0"
    patch = get_patch_version()
    return f"{major}.{minor}.{patch}"


def generate_app_conf(app, version):
    """Generate default/app.conf from contentctl.yml app block."""
    return (
        "[install]\n"
        "build = 1\n"
        "is_configured = 0\n"
        "state = enabled\n"
        "\n"
        "[ui]\n"
        "is_visible = 1\n"
        f"label = {app.get('title', app['appid'])}\n"
        "\n"
        "[launcher]\n"
        f"author = {app.get('author_name', '')}\n"
        f"description = {app.get('description', '')}\n"
        f"version = {version}\n"
        "\n"
        "[id]\n"
        f"name = {app['appid']}\n"
        f"version = {version}\n"
    )


def concat_conf_files(directory):
    """Concatenate all .conf files in a directory into a single string."""
    conf_files = sorted(glob.glob(os.path.join(directory, "**", "*.conf"), recursive=True))
    if not conf_files:
        return None
    stanzas = []
    for path in conf_files:
        with open(path) as f:
            stanzas.append(f.read().strip())
    return "\n\n".join(stanzas) + "\n"


def strip_gitkeeps(directory):
    """Remove .gitkeep files and any directories they leave empty."""
    for path in glob.glob(os.path.join(directory, "**", ".gitkeep"), recursive=True):
        os.remove(path)
    for dirpath, _, filenames in os.walk(directory, topdown=False):
        if not os.listdir(dirpath) and dirpath != directory:
            try:
                os.rmdir(dirpath)
            except OSError:
                pass


def resolve_template_vars(text, data):
    """Replace %name%, %description%, %original_detection_search% in a string."""
    if not isinstance(text, str):
        return str(text)
    name = data.get("name", "")
    desc = data.get("description", "")
    if isinstance(desc, list):
        desc = " ".join(str(d) for d in desc)
    search = data.get("search", "")
    return text.replace("%name%", name).replace("%description%", str(desc)).replace("%original_detection_search%", search)


def extract_macros_from_yaml(data):
    """Extract macros from parsed YAML data and return macros.conf stanza(s)."""
    macros = data.get("macros", [])
    if not macros:
        return None
    stanzas = []
    for macro in macros:
        macro_name = macro["name"]
        args = macro.get("arguments", [])
        header = f"[{macro_name}({len(args)})]" if args else f"[{macro_name}]"
        lines = [header]
        lines.append(f"definition = {macro['definition']}")
        if args:
            lines.append(f"args = {', '.join(args)}")
        if macro.get("description"):
            lines.append(f"description = {macro['description']}")
        stanzas.append("\n".join(lines))
    return "\n\n".join(stanzas)


def convert_yaml_to_conf(yaml_path):
    """Convert a YAML detection file to a savedsearches.conf stanza.

    Returns: (savedsearch_stanza: str, macros_stanza: str or None)
    """
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    name = data.get("name", "Unknown")
    desc = data.get("description", "")
    if isinstance(desc, list):
        desc = " ".join(str(d) for d in desc)
    search = data.get("search", "")
    scheduling = data.get("scheduling", {})
    notable = data.get("alert_action", {}).get("notable", {})
    rba = data.get("rba", {})
    drilldowns = data.get("drilldown_searches", [])
    annotations = data.get("annotations", {})

    # Stanza header: [Domain - Name - Rule]
    domain = notable.get("domain", "")
    if domain:
        stanza_name = f"{domain.title()} - {name} - Rule"
    else:
        stanza_name = f"{name} - Rule"

    # Build key-value pairs (will be sorted alphabetically)
    kv = {}

    # --- Correlation search ---
    if annotations:
        kv["action.correlationsearch.annotations"] = json.dumps(annotations, separators=(",", ":"))
    kv["action.correlationsearch.detection_type"] = data.get("type", "ebd")
    kv["action.correlationsearch.enabled"] = "1"
    kv["action.correlationsearch.label"] = name

    # --- Notable (alert_action) ---
    if notable and notable.get("enabled"):
        kv["action.notable"] = "1"
        entities = []
        if notable.get("field"):
            entities.append({
                "risk_object_field": notable["field"],
                "risk_object_type": notable.get("type", "other"),
                "risk_score": notable.get("score", 0)
            })
        kv["action.notable.param._entities"] = json.dumps(entities)
        dd_list = []
        for dd in drilldowns:
            dd_list.append({
                "name": resolve_template_vars(dd.get("name", ""), data),
                "search": resolve_template_vars(dd.get("search", ""), data),
                "earliest_offset": dd.get("earliest_offset", "$info_min_time$"),
                "latest_offset": dd.get("latest_offset", "$info_max_time$")
            })
        kv["action.notable.param.drilldown_searches"] = json.dumps(dd_list)
        kv["action.notable.param.rule_description"] = resolve_template_vars(
            notable.get("rule_description", name), data
        )
        kv["action.notable.param.rule_title"] = resolve_template_vars(
            notable.get("rule_title", name), data
        )
        kv["action.notable.param.security_domain"] = notable.get("domain", "threat")
        kv["action.notable.param.severity"] = notable.get("severity", "medium")
    else:
        kv["action.notable"] = "0"

    # --- Risk (RBA) ---
    if rba and rba.get("enabled"):
        kv["action.risk"] = "1"
        risk_list = []
        for ro in rba.get("risk_objects", []):
            risk_list.append({
                "risk_object_field": ro["field"],
                "risk_object_type": ro.get("type", "other"),
                "risk_score": ro.get("score", 0)
            })
        for to in rba.get("threat_objects", []):
            risk_list.append({
                "threat_object_field": to["field"],
                "threat_object_type": to.get("type", "other")
            })
        kv["action.risk.param._risk"] = json.dumps(risk_list)
        risk_msg = rba.get("message", "")
        if isinstance(risk_msg, list):
            risk_msg = " ".join(str(m) for m in risk_msg)
        kv["action.risk.param._risk_message"] = resolve_template_vars(risk_msg, data)
    else:
        kv["action.risk"] = "0"

    kv["cron_schedule"] = scheduling.get("cron_schedule", "0 * * * *")
    kv["description"] = desc
    kv["disabled"] = "0" if data.get("enabled_by_default", False) else "1"
    kv["dispatch.earliest_time"] = scheduling.get("earliest_time", "-24h")
    kv["dispatch.latest_time"] = scheduling.get("latest_time", "now")
    kv["enableSched"] = "1"
    kv["request.ui_dispatch_app"] = "SplunkEnterpriseSecuritySuite"
    kv["run_on_startup"] = "True"
    sw = scheduling.get("schedule_window")
    if sw:
        kv["schedule_window"] = str(sw)
    kv["search"] = search

    # --- Assemble stanza (sorted alphabetically) ---
    lines = [f"[{stanza_name}]"]
    for key in sorted(kv.keys()):
        lines.append(f"{key} = {kv[key]}")

    macros_stanza = extract_macros_from_yaml(data)
    return "\n".join(lines), macros_stanza


def build_savedsearches(directory):
    """Build savedsearches.conf content from .conf and .yml files.

    Returns: (savedsearches_content: str or None, yaml_macros: str or None)
    """
    stanzas = []
    all_yaml_macros = []

    # Existing .conf files (unchanged behavior)
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.conf"), recursive=True)):
        with open(path) as f:
            stanzas.append(f.read().strip())

    # Convert .yml files
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.yml"), recursive=True)):
        try:
            ss_stanza, macros_stanza = convert_yaml_to_conf(path)
            stanzas.append(ss_stanza)
            if macros_stanza:
                all_yaml_macros.append(macros_stanza)
        except Exception as e:
            print(f"WARNING: Failed to convert {path}: {e}")

    savedsearches = "\n\n".join(stanzas) + "\n" if stanzas else None
    yaml_macros = "\n\n".join(all_yaml_macros) if all_yaml_macros else None
    return savedsearches, yaml_macros


def main():
    with open(APP_BUILD_YML) as f:
        config = yaml.safe_load(f)

    app     = config["app"]
    appid   = app["appid"]
    version = get_version(app)
    name    = f"{appid}_{version}"

    app_dir     = os.path.join(DIST_DIR, name)
    default_dir = os.path.join(app_dir, "default")

    # Clean previous build (ignore_errors for Windows file locking)
    if os.path.exists(app_dir):
        shutil.rmtree(app_dir, ignore_errors=True)
    os.makedirs(default_dir, exist_ok=True)

    # --- Copy app_template into the app ---
    if os.path.exists(APP_TEMPLATE):
        for item in ["metadata", "static", "README", "lookups"]:
            src = os.path.join(APP_TEMPLATE, item)
            if os.path.exists(src):
                shutil.copytree(src, os.path.join(app_dir, item), dirs_exist_ok=True)
        # default/data/ (nav, views, etc.)
        src_data = os.path.join(APP_TEMPLATE, "default", "data")
        if os.path.exists(src_data):
            shutil.copytree(src_data, os.path.join(default_dir, "data"), dirs_exist_ok=True)

    # --- Copy any lookup files from root lookups/ ---
    if os.path.exists(LOOKUPS_DIR):
        dst = os.path.join(app_dir, "lookups")
        os.makedirs(dst, exist_ok=True)
        for item in glob.glob(os.path.join(LOOKUPS_DIR, "*")):
            if os.path.isfile(item):
                shutil.copy2(item, dst)

    # --- Copy dashboard XMLs into default/data/ui/views/ ---
    if os.path.exists(DASHBOARDS_DIR):
        views_dir = os.path.join(default_dir, "data", "ui", "views")
        os.makedirs(views_dir, exist_ok=True)
        for item in glob.glob(os.path.join(DASHBOARDS_DIR, "*.xml")):
            shutil.copy2(item, views_dir)

    # --- Generate conf files ---
    with open(os.path.join(default_dir, "app.conf"), "w") as f:
        f.write(generate_app_conf(app, version))

    saved_searches, yaml_macros = build_savedsearches(DETECTIONS_DIR)
    if saved_searches:
        with open(os.path.join(default_dir, "savedsearches.conf"), "w") as f:
            f.write(saved_searches)

    macros_parts = []
    conf_macros = concat_conf_files(MACROS_DIR)
    if conf_macros:
        macros_parts.append(conf_macros.strip())
    if yaml_macros:
        macros_parts.append(yaml_macros.strip())
    if macros_parts:
        with open(os.path.join(default_dir, "macros.conf"), "w") as f:
            f.write("\n\n".join(macros_parts) + "\n")

    # --- Clean up .gitkeep artifacts ---
    strip_gitkeeps(app_dir)

    # --- Package as .tgz (arcname=appid so Splunk sees the right app name) ---
    tgz_path = os.path.join(DIST_DIR, f"{name}.tgz")
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(app_dir, arcname=appid)

    print(f"Version: {version}")
    print(f"Built: {tgz_path}")
    print(f"Extracted app: {app_dir}")


if __name__ == "__main__":
    main()
