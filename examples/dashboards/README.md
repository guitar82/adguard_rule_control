# Example Dashboards

These dashboards use only built-in Home Assistant cards. No custom dashboard
cards are required.

## Choose an Example

- `family-dashboard.yaml`: a simple shared dashboard with status, profiles,
  quick actions, and controls for two people or devices.
- `mobile-dashboard.yaml`: a compact one-column layout for phones and tablets.
- `admin-dashboard.yaml`: a detailed owner view with connection, activity,
  profiles, and every managed control.

## Add an Example

1. Download the YAML file you want.
2. In Home Assistant, open the dashboard where you want the new view.
3. Select **Edit dashboard**, open the three-dot menu, and select **Raw
   configuration editor**.
4. Copy the example view from below `views:` into your dashboard's existing
   `views:` list. To create a separate YAML dashboard instead, use the complete
   file as-is.
5. Replace every entity ID containing `replace_with_` with the matching entity
   from your AdGuard Rule Control devices.
6. Save the dashboard.

Entity IDs are shown in Home Assistant under **Settings > Devices & services >
Entities**. Search for `AdGuard Rule Control`, open an entity, and select its
settings button to see or copy the entity ID.

The example names are intentionally generic. Remove cards you do not need and
duplicate the person/device section for additional family members.
