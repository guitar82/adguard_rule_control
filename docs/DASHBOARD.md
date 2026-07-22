# Native Home Assistant Dashboard

AdGuard Rule Control is designed to work with Home Assistant's built-in Sections and Tile cards. No custom dashboard card is required.

## Recommended Layout

Create a dashboard named **Internet Controls** with these sections.

### Status

Add these entities from the main **AdGuard Rule Control** device:

- Any Block Active
- Active Blocks
- Next Automatic Change
- Connected
- Last Sync

The Active Blocks entity includes the names of currently enabled controls. Next Automatic Change shows when the next temporary block or temporary allowance will restore its previous state.

### Quick Actions

Add these buttons from the main device:

- Allow Everything
- Sync

Allow Everything disables every managed control with one AdGuard update. It does not disable AdGuard protection or change filters that are not owned by this integration.

### Profiles

Add profile switches such as **Bedtime**, **Homework**, **Dinner**, or **School Night**. Create and edit profiles from:

```text
Settings > Devices & services > AdGuard Rule Control > Configure
```

Each profile switch changes all of its selected controls with one synchronized AdGuard update.

### People and Devices

Client-specific controls are grouped into their own Home Assistant devices, such as **Kid Tablet Internet Controls** or **Living Room TV Internet Controls**.

1. Open **Settings > Devices & services > Devices**.
2. Open the client's Internet Controls device.
3. Select **Add to dashboard**.
4. Choose Tile cards in a Sections view.
5. Keep the normal switch, temporary block button, and temporary allow button together.

Global controls remain on the main AdGuard Rule Control device.

### Safety

For a global Block All switch, edit its Tile card and add a confirmation to the icon tap action. Home Assistant can also limit a view or card to selected users.

## Scheduling

Create a Schedule helper from **Settings > Devices & services > Helpers**, then [import the included automation blueprint](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fguitar82%2Fadguard_rule_control%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fadguard_rule_control%2Fschedule_controls.yaml):

```text
blueprints/automation/adguard_rule_control/schedule_controls.yaml
```

The blueprint accepts normal rule-control switches and profile switches. It enables them when the schedule starts and disables them when the schedule ends.

## Optional Activity

Choose **Privacy and activity settings** in the integration configuration to add:

- Blocked Requests Last 24 Hours
- Last Blocked Request

These entities inspect a limited sample of AdGuard's blocked query log. The integration keeps aggregate counts, top client names, and blocked-service names only. It does not retain requested domains or raw query-log rows.
