# AdGuard Rule Control

AdGuard Rule Control is a lightweight Home Assistant custom integration for managing AdGuard Home custom filtering rules through simple switch entities.

It connects directly to the AdGuard Home REST API, reads existing custom filtering rules, preserves unrelated rules, and replaces only the dedicated managed block owned by this integration.

## Features

- One Home Assistant switch per configured rule control
- Global AdGuard custom rules
- Client-specific rules using AdGuard's `$client` modifier
- IP address, MAC address, and AdGuard client-name targets
- Integration settings based configuration
- Persistent switch state
- Import of existing managed-block state
- Preview of generated rules before use
- Built-in presets for common services and categories
- Block-all preset for carefully targeted device controls
- Plain-English "block a website" builder
- AdGuard client discovery for easier device selection
- AdGuard blocked-services controls through the blocked-services API
- Everyone vs one-device setup wizard
- In-GUI setup instructions and custom rule examples
- Duplicate and reorder rule controls
- Optional multi-instance service targeting
- Debounced writes with a single managed rule block
- Minimal diagnostics and services
- HACS-ready repository structure

This integration does not provide accounts, PINs, schedules, timers, dashboards, penalties, profiles, or parental-control logic. Use Home Assistant automations for timing and conditions.

## Important Limitation

DNS filtering can be bypassed by VPNs, cellular data, DNS over HTTPS, DNS over TLS, hardcoded DNS servers, cached DNS responses, or applications that connect directly to IP addresses. This integration is not a firewall and does not guarantee complete internet restriction.

## HACS Installation

1. Open HACS.
2. Add `https://github.com/guitar82/adguard_rule_control` as a custom integration repository.
3. Install **AdGuard Rule Control**.
4. Restart Home Assistant.
5. Add the integration from **Settings > Devices & services**.

## Manual Installation

1. Copy `custom_components/adguard_rule_control` into your Home Assistant `custom_components` directory.
2. Restart Home Assistant.
3. Add **AdGuard Rule Control** from **Settings > Devices & services**.

## AdGuard Connection Setup

The setup flow asks for:

- Host or base URL
- Port
- Use SSL
- Verify SSL certificate
- Username
- Password

Accepted host formats include:

```text
192.168.1.10
192.168.1.10:3000
http://192.168.1.10:3000
https://adguard.example.com
http://adguard.local:3000/control
```

The integration removes a trailing `/control` suffix automatically. Credentials are sent with Basic Authentication when provided and are never logged by the integration.

## Adding a Rule Control

Open:

```text
Settings > Devices & services > AdGuard Rule Control > Configure
```

Choose **add**, then follow the setup wizard:

1. Pick a preset or choose **Block a website by name**.
2. Choose whether the switch applies to one device/client or everyone.
3. Pick a discovered AdGuard client, or enter one manually.
4. Review the switch name and generated rules.
5. Save the control.

Presets pre-fill the display name, icon, and AdGuard rule list. Users can still edit the generated rules before saving.

Built-in presets include:

- YouTube
- Facebook and Instagram
- TikTok
- Snapchat
- Discord
- Reddit
- Streaming apps
- Gaming services
- Social media
- Block all internet
- Adult sites starter preset
- Custom domain block

After choosing a preset, review or adjust:

- Display name
- Whether to create a switch entity
- One or more AdGuard rules, one per line
- Target type
- Optional target display name
- Optional target identifier
- Optional icon

Renaming a rule control keeps the same unique entity because entity identity is based on the internal control ID.

The Configure flow also supports:

- Edit a rule control
- Delete a rule control
- Duplicate a rule control
- Move a rule control up or down in the managed block order
- Preview the generated managed rules for a control
- Import current enabled states from an existing AdGuard managed block
- Add a blocked-services control using AdGuard's built-in service list

The preview step uses the same generator as the live switch path, so it shows the actual rules that would be written between this integration's markers.

## Blocking One Website

For a simple website block, choose **Block a website by name** and enter a domain or URL:

```text
youtube.com
https://www.reddit.com/r/popular
```

The integration turns that into a safe AdGuard rule such as:

```text
||reddit.com^
```

## Choosing a Device

When applying a control to one device/client, the integration attempts to read clients from AdGuard Home and show them in a picker. If a device is not listed, choose manual entry and enter:

- IPv4 address
- IPv6 address
- MAC address
- Exact AdGuard client name

## Blocked Services Controls

AdGuard Home includes built-in blocked services. In Configure, choose **add_blocked_services** to query AdGuard for the available service list and create a switch that toggles one or more services.

These controls use:

```text
GET /control/blocked_services/all
GET /control/blocked_services/get
PUT /control/blocked_services/update
```

The integration preserves blocked services that were enabled outside this integration. When a blocked-services switch turns off, it removes only the service IDs it previously managed.

## Importing Existing State

If Home Assistant is restored or the integration is reinstalled while the AdGuard managed block still exists, open:

```text
Settings > Devices & services > AdGuard Rule Control > Configure
```

Choose **import_state**. The integration reads the current managed block from AdGuard, compares the generated rules for each configured control, and enables matching controls in Home Assistant storage. It does not write to AdGuard during import.

## Global Rules

Global rules are used exactly as entered:

```text
||youtube.com^
@@||allowed.example.com^
```

## Client-Specific Rules

Client-specific controls add AdGuard's `$client` modifier:

```text
||youtube.com^$client='192.168.1.25'
```

If the rule already has modifiers:

```text
||youtube.com^$important
```

the generated rule becomes:

```text
||youtube.com^$important,client='192.168.1.25'
```

## Supported Client Identifiers

- IPv4 address
- IPv6 address
- MAC address
- AdGuard client name

MAC addresses are normalized to lower-case colon format.

## Switch Usage

Each configured rule control appears as a switch, such as:

```text
switch.adguard_rule_control_block_youtube
```

Turning the switch on adds that control's rules to the managed block. Turning it off removes them. If AdGuard rejects an update or cannot be reached, the switch rolls back to its previous state.

That switch is the main entity you automate in Home Assistant. For example, a preset named **Block YouTube** will create a normal switch entity you can use in dashboards, scenes, scripts, and automations.

## Services

Force a sync:

```yaml
action: adguard_rule_control.sync
```

Enable a control:

```yaml
action: adguard_rule_control.enable
data:
  control_id: control-uuid-or-id
```

Disable a control:

```yaml
action: adguard_rule_control.disable
data:
  control_id: control-uuid-or-id
```

Set a control state:

```yaml
action: adguard_rule_control.set_state
data:
  control_id: control-uuid-or-id
  enabled: true
```

The `control_id` is exposed as an attribute on each switch entity.

If more than one AdGuard Rule Control instance is configured, services can include `entry_id`:

```yaml
action: adguard_rule_control.enable
data:
  entry_id: adguard-rule-control-entry-id
  control_id: control-uuid-or-id
```

When `entry_id` is omitted, the service resolves the control automatically if exactly one configured instance contains that `control_id`.

## Automation Example

Use the switch entity directly:

```yaml
alias: Block YouTube now
triggers: []
actions:
  - action: switch.turn_on
    target:
      entity_id: switch.adguard_rule_control_block_youtube
```

```yaml
alias: Block streaming at bedtime
triggers:
  - trigger: time
    at: "21:00:00"
actions:
  - action: adguard_rule_control.enable
    data:
      control_id: control-uuid-or-id
```

```yaml
alias: Restore streaming in the morning
triggers:
  - trigger: time
    at: "07:00:00"
actions:
  - action: adguard_rule_control.disable
    data:
      control_id: control-uuid-or-id
```

## Managed Rule Safety

The integration owns only rules between these markers:

```text
! ADGUARD RULE CONTROL START
! ADGUARD RULE CONTROL END
```

On every write it:

1. Reads current AdGuard custom rules.
2. Verifies the managed markers are valid.
3. Removes only the previous managed block.
4. Preserves every rule outside the managed block.
5. Appends the newly generated managed block.
6. Writes the full rule list back to AdGuard.

If markers are malformed, duplicated, nested, or incomplete, the integration refuses to write.

## Diagnostics

The integration creates:

- `binary_sensor.adguard_rule_control_connected`
- `sensor.adguard_rule_control_managed_rule_count`
- `sensor.adguard_rule_control_last_sync`
- `button.adguard_rule_control_sync`

The last sanitized error is exposed as an entity attribute.

Each rule-control switch also exposes lightweight attributes:

- `control_id`
- `generated_rule_count`
- `last_generated_checksum`
- `last_successful_sync`
- `last_error`

## Troubleshooting

- Confirm AdGuard Home is reachable from Home Assistant.
- Confirm the AdGuard Home port is correct.
- If using HTTPS with a self-signed certificate, disable certificate verification in the integration settings.
- Confirm credentials can read and write custom filtering rules.
- Check AdGuard custom filtering rules for incomplete or duplicated managed markers.
- Remember that DNS clients may cache results after a rule changes.

## Removal

1. Turn off all rule control switches or call `adguard_rule_control.sync` after disabling controls.
2. Remove the integration from Home Assistant.
3. Delete any remaining managed block from AdGuard custom filtering rules if desired.
4. Remove `custom_components/adguard_rule_control` if installed manually.

## Development

Install test dependencies:

```bash
python -m pip install ".[test]"
```

Run tests:

```bash
pytest
```

Run formatting and linting with your preferred Home Assistant development tooling.

## License

MIT
