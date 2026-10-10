# Attack Surface Monitor — Design System

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** AppFlow.md, PRD.md
> **Document Type:** Visual & Interaction Design Language

---

## 1. Design Philosophy

### Personality

The Attack Surface Monitor communicates:

| Trait | Expression |
|---|---|
| **Professional** | Clean layouts, consistent spacing, restrained use of color |
| **Trustworthy** | Evidence-backed claims, transparent confidence levels, no inflated alerts |
| **Technically Sophisticated** | Precise data presentation, monospaced technical data, structured information |
| **Calm** | Neutral backgrounds, measured color use; urgency through intent, not visual noise |
| **Precise** | Exact timestamps, specific asset identifiers, detailed evidence chains |
| **Intelligent** | Contextual information surfaced at the right moment; smart defaults |
| **Operational** | Workflow-oriented; every screen leads to an action or decision |

### Anti-Patterns

- ❌ Cyberpunk / hacker aesthetic (neon, terminal-everything, matrix effects)
- ❌ Gratuitous animation or particle effects
- ❌ Generic dashboard templates with meaningless KPIs
- ❌ Dark-on-dark with insufficient contrast
- ❌ Competitor visual cloning
- ❌ Marketing language in operational interfaces

---

## 2. Color System

### Core Palette

The palette is built on HSL for systematic control. Cool neutrals communicate professionalism; accent colors are reserved for semantic meaning.

#### Neutrals (Background / Surface / Text)

| Token | Light Mode | Dark Mode | Usage |
|---|---|---|---|
| `--color-bg-primary` | `hsl(220, 20%, 98%)` | `hsl(222, 25%, 10%)` | Page background |
| `--color-bg-secondary` | `hsl(220, 16%, 94%)` | `hsl(222, 22%, 14%)` | Card/panel background |
| `--color-bg-tertiary` | `hsl(220, 14%, 90%)` | `hsl(222, 20%, 18%)` | Elevated surface, hover |
| `--color-bg-inverse` | `hsl(222, 25%, 10%)` | `hsl(220, 20%, 98%)` | Inverted sections |
| `--color-border-primary` | `hsl(220, 12%, 86%)` | `hsl(222, 16%, 22%)` | Primary borders |
| `--color-border-secondary` | `hsl(220, 10%, 92%)` | `hsl(222, 14%, 16%)` | Subtle borders |
| `--color-text-primary` | `hsl(222, 25%, 12%)` | `hsl(220, 16%, 92%)` | Primary text |
| `--color-text-secondary` | `hsl(220, 12%, 45%)` | `hsl(220, 12%, 60%)` | Secondary text |
| `--color-text-tertiary` | `hsl(220, 10%, 58%)` | `hsl(220, 10%, 48%)` | Muted text, labels |
| `--color-text-inverse` | `hsl(220, 16%, 92%)` | `hsl(222, 25%, 12%)` | Text on inverse bg |

#### Semantic Colors

| Token | Value | Usage |
|---|---|---|
| `--color-accent` | `hsl(215, 85%, 52%)` | Primary actions, links, interactive elements |
| `--color-accent-hover` | `hsl(215, 85%, 45%)` | Hover state for accent |
| `--color-accent-subtle` | `hsl(215, 60%, 95%)` / dark: `hsl(215, 60%, 18%)` | Accent background |
| `--color-success` | `hsl(145, 65%, 42%)` | Success states, verified, resolved |
| `--color-success-subtle` | `hsl(145, 50%, 94%)` / dark: `hsl(145, 40%, 16%)` | Success background |
| `--color-warning` | `hsl(38, 90%, 50%)` | Warning states, approaching expiry |
| `--color-warning-subtle` | `hsl(38, 70%, 94%)` / dark: `hsl(38, 50%, 16%)` | Warning background |
| `--color-danger` | `hsl(0, 72%, 51%)` | Destructive actions, critical severity |
| `--color-danger-subtle` | `hsl(0, 60%, 95%)` / dark: `hsl(0, 50%, 16%)` | Danger background |
| `--color-info` | `hsl(200, 80%, 50%)` | Informational, tips |
| `--color-info-subtle` | `hsl(200, 60%, 94%)` / dark: `hsl(200, 50%, 16%)` | Info background |

#### Severity Colors

| Severity | Color | Badge BG | Usage |
|---|---|---|---|
| **Critical** | `hsl(0, 85%, 48%)` | `hsl(0, 75%, 94%)` / dark: `hsl(0, 60%, 18%)` | Critical findings |
| **High** | `hsl(20, 85%, 52%)` | `hsl(20, 70%, 94%)` / dark: `hsl(20, 55%, 18%)` | High severity |
| **Medium** | `hsl(38, 90%, 50%)` | `hsl(38, 70%, 94%)` / dark: `hsl(38, 50%, 16%)` | Medium severity |
| **Low** | `hsl(200, 70%, 50%)` | `hsl(200, 55%, 94%)` / dark: `hsl(200, 45%, 16%)` | Low severity |
| **Informational** | `hsl(220, 12%, 55%)` | `hsl(220, 10%, 94%)` / dark: `hsl(220, 12%, 20%)` | Informational |

### Dark/Light Strategy

**DECISION:** Dark mode is the default. Light mode is available.

**WHY:** Security teams often work in SOC environments with reduced lighting. The product's target persona (security engineers) overwhelmingly prefers dark interfaces for operational tools.

**IMPLEMENTATION:** CSS custom properties (design tokens) toggled via `data-theme` attribute on `<html>`. No FOUC — theme preference stored in cookie and applied server-side via Next.js.

---

## 3. Typography

### Font Stack

| Usage | Font | Fallback | Reason |
|---|---|---|---|
| **Primary (UI)** | Inter | system-ui, sans-serif | Excellent readability at all sizes; tabular numbers available; professional |
| **Monospace (Technical)** | JetBrains Mono | ui-monospace, monospace | Clear character distinction; designed for technical content |

Both fonts are loaded from Google Fonts with `font-display: swap`.

### Type Scale

| Token | Size | Weight | Line Height | Usage |
|---|---|---|---|---|
| `--text-xs` | 11px | 400 | 1.45 | Badges, timestamps, fine print |
| `--text-sm` | 13px | 400 | 1.45 | Secondary text, table cells, labels |
| `--text-base` | 14px | 400 | 1.55 | Body text, form inputs |
| `--text-md` | 15px | 500 | 1.5 | Emphasized body, nav items |
| `--text-lg` | 17px | 600 | 1.4 | Section headings, card titles |
| `--text-xl` | 20px | 600 | 1.35 | Page section titles |
| `--text-2xl` | 24px | 700 | 1.3 | Page titles |
| `--text-3xl` | 30px | 700 | 1.25 | Dashboard metrics (large numbers) |
| `--text-mono-sm` | 12px | 400 | 1.5 | IP addresses, ports, technical IDs |
| `--text-mono-base` | 13px | 400 | 1.55 | Code blocks, certificates, DNS records |

### Font Weight

| Token | Weight | Usage |
|---|---|---|
| `--font-normal` | 400 | Body text |
| `--font-medium` | 500 | Emphasized text, labels |
| `--font-semibold` | 600 | Headings, important labels |
| `--font-bold` | 700 | Page titles, metrics |

---

## 4. Spacing & Layout

### Spacing Scale

Based on a 4px grid with deliberate jumps:

| Token | Value | Usage |
|---|---|---|
| `--space-1` | 4px | Tight internal spacing (badge padding) |
| `--space-2` | 8px | Compact spacing (between related elements) |
| `--space-3` | 12px | Default element spacing |
| `--space-4` | 16px | Card internal padding |
| `--space-5` | 20px | Section padding |
| `--space-6` | 24px | Card gaps, section separators |
| `--space-8` | 32px | Major section gaps |
| `--space-10` | 40px | Page section spacing |
| `--space-12` | 48px | Large section gaps |
| `--space-16` | 64px | Page-level spacing |

### Grid & Layout

| Token | Value | Notes |
|---|---|---|
| `--layout-max-width` | 1440px | Maximum content width |
| `--layout-content-width` | 1200px | Typical content area |
| `--layout-sidebar-width` | 240px | Navigation sidebar |
| `--layout-sidebar-collapsed` | 64px | Collapsed sidebar (icon-only) |
| `--layout-page-padding` | 24px | Page edge padding |
| `--layout-card-radius` | 8px | Card border radius |
| `--layout-input-radius` | 6px | Input/button border radius |
| `--layout-badge-radius` | 4px | Badge border radius |

### Breakpoints

| Token | Width | Layout Change |
|---|---|---|
| `--bp-sm` | 640px | Single column; sidebar hidden |
| `--bp-md` | 768px | Sidebar collapsed; responsive tables |
| `--bp-lg` | 1024px | Full sidebar; 2-column layouts |
| `--bp-xl` | 1280px | Expanded content; 3-column layouts |
| `--bp-2xl` | 1536px | Max-width content centering |

---

## 5. Navigation

### Primary Navigation (Sidebar)

```
┌────────────────────────┐
│  ◆ ASM Logo            │
│                        │
│  📊 Dashboard          │
│  🔍 Assets             │
│  ⚡ Changes            │
│  🎯 Findings           │
│  📋 Decisions          │
│                        │
│  ─── MANAGE ───        │
│  🌐 Domains            │
│  👥 Members            │
│  ⚙️ Settings            │
│                        │
│  ─── ─── ───           │
│  📖 Audit Log          │
│  🔔 Notifications (3)  │
│                        │
│  ─── ─── ───           │
│  👤 User Menu ▼        │
│     Profile             │
│     Security            │
│     Log Out             │
└────────────────────────┘
```

- Sidebar is persistent on desktop (≥ 1024px)
- Collapsible to icon-only
- Hidden on mobile, accessible via hamburger menu
- Active page highlighted with accent color left border
- Notification badge shows unread count

### Breadcrumbs

Used on detail pages for navigation context:

```
Dashboard > Assets > app.example.com > Services
```

---

## 6. Component System

### Cards

- Background: `--color-bg-secondary`
- Border: 1px solid `--color-border-primary`
- Border radius: `--layout-card-radius` (8px)
- Padding: `--space-4` (16px) to `--space-6` (24px)
- Shadow: none (flat design with borders)
- Hover: `--color-bg-tertiary` for interactive cards

### Tables

- Header: `--color-bg-tertiary`, `--text-sm`, `--font-semibold`, uppercase
- Rows: Alternating subtle background (`--color-bg-primary` / `--color-bg-secondary`)
- Borders: Horizontal only (`--color-border-secondary`)
- Row hover: `--color-bg-tertiary`
- Cell padding: `--space-3` vertical, `--space-4` horizontal
- Sortable columns: Sort icon indicator; active sort highlighted
- Technical data (IPs, hostnames): Monospaced font

### Badges / Tags

- Border radius: `--layout-badge-radius` (4px)
- Padding: `--space-1` vertical, `--space-2` horizontal
- Font: `--text-xs`, `--font-medium`
- Variants: Severity (color-coded), Status (outlined), Environment (filled), Technology (neutral)

### Buttons

| Variant | Usage | Styling |
|---|---|---|
| **Primary** | Primary actions | Filled accent color, white text |
| **Secondary** | Alternative actions | Bordered, accent text |
| **Danger** | Destructive actions | Filled danger color, white text |
| **Ghost** | Tertiary actions | Transparent, text color on hover |
| **Icon** | Toolbar/compact actions | Icon-only with tooltip |

- Border radius: `--layout-input-radius` (6px)
- Height: 36px (default), 32px (compact), 40px (large)
- Disabled: 50% opacity, pointer-events: none
- Loading: Spinner replaces text/icon

### Forms

- Input height: 36px
- Label: `--text-sm`, `--font-medium`, `--color-text-secondary`
- Placeholder: `--color-text-tertiary`
- Focus: 2px accent outline, no background change
- Error: Red border, error message below in `--text-xs`, `--color-danger`
- Disabled: Reduced opacity, no interaction

### Modals

- Overlay: `hsla(0, 0%, 0%, 0.5)`
- Modal: `--color-bg-secondary`, `--layout-card-radius`, max-width 520px
- Header: Title + close button
- Body: Scrollable if needed
- Footer: Action buttons (right-aligned)
- Animation: Fade-in overlay + scale-up modal (150ms ease-out)
- Close on: Escape key, overlay click, close button

---

## 7. Dashboard Components

### Metric Cards

```
┌──────────────────────┐
│  Total Assets         │
│  1,247               │  ← --text-3xl, --font-bold
│  ↑ 23 this week       │  ← --text-sm, --color-success
└──────────────────────┘
```

### Severity Distribution

Horizontal bar or segmented bar showing finding distribution:

```
Critical ████░░░░░░  12
High     ██████░░░░  34
Medium   ████████░░  56
Low      █████████░  89
```

Colors match severity color tokens. Click severity segment to filter findings.

### Change Timeline

Vertical timeline with change type icons:

```
● 14:32  New subdomain: api-v2.example.com          [Production]
● 12:15  Certificate renewed: *.example.com          [Expected]
● 09:44  New service: 1.2.3.4:8080 (HTTP)            [Unknown Owner]
● Yesterday
● 18:20  Subdomain removed: old-staging.example.com  [Staging]
```

---

## 8. Data Visualization

### Charts

| Chart Type | Usage | Library |
|---|---|---|
| **Area chart** | Asset count over time, finding trends | Recharts |
| **Horizontal bar** | Severity distribution, technology breakdown | Recharts |
| **Donut chart** | Asset type distribution, environment split | Recharts |
| **Timeline** | Change history, scan history | Custom |

### Chart Styling

- Background: transparent (inherits card background)
- Grid lines: `--color-border-secondary`, dashed
- Axis labels: `--text-xs`, `--color-text-tertiary`
- Data colors: Use semantic colors for meaningful data; use a curated palette for categorical data
- Tooltips: Card-style with `--color-bg-inverse`, `--color-text-inverse`
- Animation: Smooth entry animation (300ms ease-out)
- Responsive: Charts resize with container; hide axis labels on small screens

---

## 9. Status System

### Asset Status

| Status | Color | Badge Style |
|---|---|---|
| **Active** | Success | Filled |
| **Inactive** | Tertiary | Outlined |
| **New** | Accent | Filled |
| **Removed** | Danger | Outlined |

### Finding Status

| Status | Color | Badge Style |
|---|---|---|
| **New** | Accent | Filled |
| **Acknowledged** | Info | Outlined |
| **In Progress** | Warning | Filled |
| **Remediated** | Success (muted) | Outlined |
| **Verified** | Success | Filled |
| **Accepted Risk** | Warning | Outlined, with timer icon |
| **False Positive** | Tertiary | Outlined, strikethrough text |

### Domain Status

| Status | Color | Badge Style |
|---|---|---|
| **Verified** | Success | Filled |
| **Pending** | Warning | Filled |
| **Failed** | Danger | Outlined |
| **Expired** | Danger | Filled |

---

## 10. Loading States

- **Page load:** Skeleton loading (pulsing neutral shapes matching layout)
- **Table load:** Skeleton rows (5 rows of pulsing rectangles)
- **Button loading:** Spinner replacing button text (button width maintained)
- **Card loading:** Skeleton matching card internal layout
- **Inline loading:** Small spinner next to relevant element
- **Progress:** Determinate progress bar for scan progress; indeterminate for unknown duration

### Skeleton Styling

- Color: `--color-bg-tertiary`
- Animation: Subtle pulse (opacity 0.4 → 0.8, 1.5s ease-in-out, infinite)
- Border radius: Matches the element being loaded

---

## 11. Empty States

Every list/table/feed has an empty state:

| Context | Message | Action |
|---|---|---|
| **No assets** | "No assets discovered yet" | "Verify a domain to begin discovery" (link to domains) |
| **No findings** | "No findings detected" | "Findings will appear after discovery completes" |
| **No changes** | "No changes detected" | "Changes appear after the second scan completes" |
| **No decisions** | "No decisions made yet" | "Make decisions on findings to track your security governance" |
| **No notifications** | "You're all caught up" | (none needed) |
| **No audit events** | "No audit events recorded" | (none needed) |

Empty states use a subtle illustration/icon + descriptive text + optional CTA button.

---

## 12. Accessibility

### Requirements

| Requirement | Standard |
|---|---|
| **Contrast ratio** | WCAG 2.1 AA (4.5:1 text, 3:1 large text) |
| **Keyboard navigation** | All interactive elements reachable via Tab |
| **Focus indicators** | Visible focus ring (2px accent outline) |
| **Screen readers** | Semantic HTML, ARIA labels where needed |
| **Motion** | Respect `prefers-reduced-motion` |
| **Color independence** | Never rely on color alone to convey meaning (use icons + text) |

### Implementation

- Use Radix UI primitives (accessibility built-in)
- All severity indicators use color + icon + label
- All interactive elements have visible focus states
- Form errors announced to screen readers
- Navigation landmark regions defined

---

## 13. Responsive Behavior

| Breakpoint | Layout Changes |
|---|---|
| **< 640px** | Single column; sidebar → bottom nav; tables → cards; modals → full-screen |
| **640–768px** | Sidebar collapsed (icon-only); responsive tables; stacked form layouts |
| **768–1024px** | Sidebar expanded; 2-column layouts; standard tables |
| **> 1024px** | Full layout; 3-column where applicable; expanded data tables |

---

## 14. Motion & Animation

### Principles

- Motion serves function, not decoration
- Transitions are short (100–200ms for micro-interactions, 300ms for page transitions)
- Easing: `ease-out` for entries, `ease-in` for exits, `ease-in-out` for state changes
- Respect `prefers-reduced-motion`

### Animation Tokens

| Token | Value | Usage |
|---|---|---|
| `--transition-fast` | 100ms ease-out | Hover states, toggles |
| `--transition-base` | 150ms ease-out | Button clicks, dropdowns |
| `--transition-slow` | 300ms ease-out | Modal entry, page transitions |
| `--transition-skeleton` | 1.5s ease-in-out infinite | Skeleton loading pulse |

### Specific Animations

| Element | Animation |
|---|---|
| **Sidebar toggle** | Width transition (150ms) |
| **Modal open** | Overlay fade (150ms) + modal scale 0.95→1 (150ms) |
| **Dropdown** | Opacity + translateY(4px→0) (100ms) |
| **Notification badge** | Scale pulse on new notification (300ms) |
| **Toast** | Slide in from right + fade (200ms) |
| **Skeleton** | Opacity pulse (1.5s infinite) |
| **Chart data** | Path draw (300ms ease-out) |
