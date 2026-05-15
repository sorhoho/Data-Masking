---
version: alpha
name: Data Masking Admin
description: Internal admin portal for data masking policy management. Dark top nav, light content area, Bootstrap 5.3 base.

colors:
  # Surface
  surface: "#f8f9fa"
  surface-nav: "#212529"
  surface-card: "#ffffff"
  surface-muted: "#e9ecef"

  # Brand / semantic
  primary: "#0d6efd"
  success: "#198754"
  warning: "#ffc107"
  danger: "#dc3545"
  info: "#0dcaf0"
  secondary: "#6c757d"

  # Tier / severity badges
  tier-vip: "#dc3545"
  tier-premium: "#fd7e14"
  tier-risk: "#6f42c1"
  tier-standard: "#198754"

  # Text
  on-surface: "#212529"
  on-nav: "#f8f9fa"
  muted: "#6c757d"

typography:
  body-md:
    fontFamily: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  body-sm:
    fontFamily: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.4
  label-md:
    fontFamily: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
    fontSize: 14px
    fontWeight: 600
    lineHeight: 1.5
  label-sm:
    fontFamily: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
    fontSize: 12px
    fontWeight: 600
    lineHeight: 1.4
  heading-lg:
    fontFamily: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
    fontSize: 20px
    fontWeight: 700
    lineHeight: 1.3
  code:
    fontFamily: "SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.5

rounded:
  none: 0px
  sm: 4px
  md: 6px
  lg: 8px
  full: 9999px

spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
  xxl: 32px

components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: 6px 12px
    typography: "{typography.label-md}"

  button-primary-outline:
    backgroundColor: "transparent"
    textColor: "{colors.primary}"
    rounded: "{rounded.md}"
    padding: 4px 10px

  button-warning-outline:
    backgroundColor: "transparent"
    textColor: "{colors.warning}"
    rounded: "{rounded.md}"
    padding: 4px 10px

  button-danger-outline:
    backgroundColor: "transparent"
    textColor: "{colors.danger}"
    rounded: "{rounded.md}"
    padding: 4px 10px

  card:
    backgroundColor: "{colors.surface-card}"
    rounded: "{rounded.lg}"
    padding: "{spacing.xl}"

  navbar:
    backgroundColor: "{colors.surface-nav}"
    textColor: "{colors.on-nav}"
    padding: 8px 16px

  badge-success:
    backgroundColor: "{colors.success}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  badge-danger:
    backgroundColor: "{colors.danger}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  badge-warning:
    backgroundColor: "{colors.warning}"
    textColor: "#212529"
    rounded: "{rounded.full}"
    padding: 2px 8px

  badge-secondary:
    backgroundColor: "{colors.secondary}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px

  table-header:
    backgroundColor: "{colors.surface-nav}"
    textColor: "{colors.on-nav}"
    typography: "{typography.label-sm}"

  alert-success:
    backgroundColor: "#d1e7dd"
    textColor: "#0f5132"
    rounded: "{rounded.md}"

  alert-danger:
    backgroundColor: "#f8d7da"
    textColor: "#842029"
    rounded: "{rounded.md}"

  alert-warning:
    backgroundColor: "#fff3cd"
    textColor: "#664d03"
    rounded: "{rounded.md}"

  alert-info:
    backgroundColor: "#cff4fc"
    textColor: "#055160"
    rounded: "{rounded.md}"

  badge-info:
    backgroundColor: "{colors.info}"
    textColor: "#000000"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  tier-badge-vip:
    backgroundColor: "{colors.tier-vip}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  tier-badge-premium:
    backgroundColor: "{colors.tier-premium}"
    textColor: "#212529"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  tier-badge-risk:
    backgroundColor: "{colors.tier-risk}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  tier-badge-standard:
    backgroundColor: "{colors.tier-standard}"
    textColor: "#ffffff"
    rounded: "{rounded.full}"
    padding: 2px 8px
    typography: "{typography.label-sm}"

  page-surface:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"

  surface-muted:
    backgroundColor: "{colors.surface-muted}"
    textColor: "{colors.on-surface}"

  text-muted:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    typography: "{typography.body-sm}"

  input:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.md}"
    padding: 6px 12px
    typography: "{typography.body-md}"
---

# Data Masking Admin Design System

Internal admin panel for policy management, customer tier control, and OPA bundle governance. Security-critical surface: visual hierarchy must communicate severity and trust level clearly.

## Colors

Two-zone layout: dark navigation rail (`#212529`, Bootstrap `bg-dark`) on top, light content area (`#f8f9fa`) below. Cards are pure white on the gray field, creating subtle depth without shadows.

Semantic colors follow Bootstrap 5 defaults for team familiarity:
- **Primary** (`#0d6efd`) — primary actions, links, version badges
- **Success** (`#198754`) — active states, green checkmarks, allowed access
- **Warning** (`#ffc107`) — sync actions, partial states, tier flags
- **Danger** (`#dc3545`) — destructive actions, VIP tier badge, rejection states
- **Secondary** (`#6c757d`) — inactive badges, muted metadata, table secondary text

Tier badges use distinct colors to communicate data access risk at a glance:
- VIP → danger red (most restricted access, privileged roles only)
- Premium → orange
- Risk → purple (fraud / compliance restricted)
- Standard → green (broadest access)

## Typography

System UI font stack — no external font dependency, loads instantly, matches OS native UI feel appropriate for an internal tool. No display fonts; this is a data-dense interface.

Code and field names use monospace (`code` token) — policy field names, customer IDs, token values, JSON snippets.

Font weights: 400 for body, 600 for labels and table headers, 700 for page headings only.

## Spacing

4px base unit. Cards use `xl` (24px) internal padding. Table cells use `sm`/`md`. Gap between summary cards is `lg` (16px).

## Rounded

Minimal rounding: `md` (6px) for cards and buttons — modern but not playful. `full` only for badge pills. Never mix sharp and rounded corners in the same component group.

## Components

### Buttons

Three tiers of button prominence:
1. **button-primary** (filled blue) — single primary action per form, e.g. "Publish Version", "Save"
2. **button-*-outline** (outlined, colored border) — secondary and destructive actions in the same form row
3. **btn-sm** sizing everywhere in the admin — space is premium in dense policy tables

Nav "Sync OPA" uses `btn-outline-warning` to signal it triggers an external system. Logout uses `btn-outline-light` (white border on dark nav).

### Cards

Shadow-only borders (`border-0 shadow-sm`) — no colored card borders. Card headers use `fw-bold` label. Full-bleed tables inside cards use `p-0` card body so table borders reach the card edge.

### Tables

Dark header (`table-dark`) for primary data tables. Hover rows (`table-hover`). Status columns right-aligned. Action columns use icon buttons, no full-width buttons inside table cells. `table-success` row highlight for active/selected state (e.g. active policy version).

### Badges / Status Indicators

All status badges are pill-shaped (`rounded-full`). Text badges for binary states: active (green), inactive (light/muted). Never use color alone for critical states — always pair with a text label.

### Alerts / Flash Messages

Bootstrap dismissible alerts. Four categories map to Bootstrap: `success`, `danger`, `warning`, `info`. Flash messages appear at top of content area below nav, above page heading.

### Forms

Inline forms for quick actions (publish version, sync OPA). Full-width forms for new entity creation (add customer tier, add app). Labels above inputs always. Required fields not marked with asterisk — all fields in these forms are required unless labeled "optional".

## Do's and Don'ts

- Do use `danger` only for destructive or irreversible actions (offboard user, rollback policy)
- Don't use `primary` for more than one button per card
- Do use monospace (`code` element) for all policy field names, customer IDs, and token values
- Don't add colored card borders — shadow is the only card elevation signal
- Do show tier badge inline with customer ID anywhere a customer is referenced
- Don't use `table-striped` — `table-hover` only; striping clashes with `table-success` row states
- Do keep action buttons `btn-sm` throughout; full-size buttons only on standalone forms (login)
- Don't use `text-truncate` on policy field names — they must be fully readable
- Do pair every status badge with a text label for accessibility
- Don't use red/green alone for diff states in version compare — add icons
