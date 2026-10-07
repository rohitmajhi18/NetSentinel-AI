# Modern AI Agent Dashboard — UI Design Guidelines

## 1\. Design Direction

The interface should feel:

- **Intelligent** — information-dense without feeling technical or intimidating.
- **Calm** — avoid excessive gradients, saturated colors, and visual noise.
- **Precise** — clear hierarchy, consistent spacing, predictable interactions.
- **Premium** — subtle depth, refined typography, restrained motion.
- **Trustworthy** — status, permissions, activity, and agent actions should always be understandable.
- **Human-centered** — the user should always understand _what the agent is doing, why it is doing it, and what happens next_.

### Recommended visual language

Think:

> **Linear × Vercel × modern AI workspace**

Rather than:

> "neon futuristic AI control panel"

Avoid excessive glassmorphism, glowing borders, huge gradients, and highly saturated purple/blue UI elements.

---

# 2\. Core Layout

Use a **three-zone application architecture**.

```
┌─────────────────────────────────────────────────────────────┐
│ Top Bar                                      User / Settings │
├───────────────┬─────────────────────────────┬───────────────┤
│               │                             │               │
│   Sidebar     │       Main Workspace        │   Context     │
│               │                             │    Panel      │
│  Navigation   │                             │               │
│  Agents       │                             │  Activity     │
│  Projects     │                             │  Tasks        │
│  Memory       │                             │  Details      │
│  Integrations │                             │  Logs         │
│               │                             │               │
└───────────────┴─────────────────────────────┴───────────────┘
```

### Recommended proportions

- Sidebar: **240–260px**
- Main content: **flexible**
- Context panel: **320–380px**
- Top bar: **56–64px**
- Main content padding: **24–32px**
- Card gap: **16–24px**

For smaller screens, collapse the context panel first, then the sidebar.

---

# 3\. Color System

The most important principle:

**Do not design dark mode by simply inverting light mode.**

Create two intentionally designed color systems that share the same semantic colors.

## Light Theme

| Token | Color | Usage |
| --- | --- | --- |
| Background | `#F7F8FA` | Application background |
| Surface | `#FFFFFF` | Cards / panels |
| Surface Subtle | `#F1F3F5` | Secondary surfaces |
| Border | `#E5E7EB` | Dividers |
| Primary Text | `#111827` | Headings |
| Secondary Text | `#667085` | Supporting text |
| Muted Text | `#98A2B3` | Metadata |
| Primary | `#635BFF` | Main actions |
| Primary Hover | `#5548E8` | Hover state |
| Success | `#12B76A` | Successful actions |
| Warning | `#F79009` | Warnings |
| Error | `#F04438` | Errors |
| Info | `#2E90FA` | Informational |

A slightly violet primary works well for AI products, but keep it controlled.

---

## Dark Theme

Avoid pure black.

Use a **cool charcoal / blue-black foundation**.

| Token | Color | Usage |
| --- | --- | --- |
| Background | `#0B0D10` | Application background |
| Surface | `#11151A` | Cards |
| Surface Elevated | `#171C22` | Modals / elevated panels |
| Surface Subtle | `#1B2128` | Inputs / secondary areas |
| Border | `#252B33` | Borders |
| Primary Text | `#F2F4F7` | Headings |
| Secondary Text | `#98A2B3` | Supporting text |
| Muted Text | `#667085` | Metadata |
| Primary | `#8B7CFF` | Main actions |
| Primary Hover | `#A196FF` | Hover |
| Success | `#32D583` | Success |
| Warning | `#FDB022` | Warning |
| Error | `#F97066` | Error |
| Info | `#53B1FD` | Info |

### Important

Don't use:

```
#000000
```

for the entire dashboard.

Instead:

```
#0B0D10
#11151A
#171C22
```

This creates subtle depth without relying on shadows.

---

# 4\. Color Hierarchy

A common AI dashboard mistake is making every important element colorful.

Instead, use approximately:

```
80%  Neutral surfaces
15%  Typography / borders
 5%  Accent / semantic colors
```

Primary color should primarily indicate:

- Primary CTA
- Active navigation
- Selected agent
- Important interactive states
- Focus state
- AI-generated highlights

Don't make every card purple.

---

# 5\. AI-Specific Accent System

AI-generated content can have a **distinct visual identity**, but it should remain subtle.

For example:

### AI surface

Light:

```
background: #F5F3FF
border:     #DDD6FE
accent:     #635BFF
```

Dark:

```
background: #16142A
border:     #302B55
accent:     #9B8CFF
```

Use this for:

- Agent responses
- AI suggestions
- Generated insights
- Automation recommendations
- Reasoning/status indicators

Avoid putting a bright gradient behind every AI response.

---

# 6\. Typography

Use a modern sans-serif.

Recommended:

- Inter
- Geist
- SF Pro
- IBM Plex Sans

For a premium SaaS/AI product, **Inter or Geist** are excellent defaults.

### Type scale

```
Display      32–40px / 700
Page title   24–28px / 650
Section      18–20px / 600
Body         14–16px / 400
Label        12–14px / 500
Caption      11–12px / 400
```

Avoid too many font sizes.

A dashboard should feel systematic.

---

# 7\. Spacing System

Use a **4px base grid**.

```
4px
8px
12px
16px
20px
24px
32px
40px
48px
64px
```

Recommended defaults:

```
Card padding       20–24px
Section spacing    32px
Grid gap           16px
Button padding     10px 16px
Input height       40–44px
Navigation height  40px
```

Whitespace is particularly important for AI interfaces because generated content can already be visually dense.

---

# 8\. Cards

Cards should provide structure, not decoration.

### Light

```
background: #FFFFFF
border: 1px solid #E5E7EB
radius: 12px
```

### Dark

```
background: #11151A
border: 1px solid #252B33
radius: 12px
```

Use shadows sparingly.

For dark mode, borders usually work better than shadows.

### Card hierarchy

Use three levels:

```
Level 1 — Page background
Level 2 — Standard cards
Level 3 — Elevated / active cards
```

Do not create five or six different surface colors.

---

# 9\. Border Radius

Keep the radius consistent.

Recommended:

```
Small controls     8px
Inputs             8px
Cards              12px
Large panels       16px
Modal              16px
Avatar             50%
```

Avoid mixing:

```
6px + 10px + 13px + 18px + 24px
```

throughout the product.

---

# 10\. Sidebar

The sidebar should be quiet.

### Structure

```
Logo
────────────────
Workspace selector

Overview
Agents
Tasks
Projects
Memory

────────────────
Integrations
Activity
Settings

────────────────
User profile
```

### Navigation states

Default:

```
transparent
secondary text
```

Hover:

```
surface-subtle
primary text
```

Active:

```
primary-tinted background
primary text
```

For example:

Dark active:

```
background: rgba(139,124,255,.12)
color: #A196FF
```

Don't use a large glowing active indicator.

---

# 11\. Agent Selector

The agent identity should be visually prominent.

Example:

```
┌────────────────────────────────────┐
│ ●  Research Agent             ⌄    │
│    Online · GPT-5                  │
└────────────────────────────────────┘
```

Use a small status indicator:

```
● Green   Running / Online
● Amber   Waiting
● Blue    Processing
● Red     Error
○ Gray    Offline
```

Status colors should always be paired with text where ambiguity matters.

---

# 12\. Agent Overview

A good agent overview should answer five questions immediately:

1. What is this agent?
2. What is it doing?
3. What has it accomplished?
4. What is it waiting for?
5. What can I do next?

Example:

```
Research Agent
Online · Last active 2 min ago

Current task
Analyzing competitor pricing

Progress
████████████░░ 82%

Recent activity
✓ Collected 32 sources
✓ Parsed pricing pages
● Comparing plans
○ Generate report
```

This is much more useful than simply displaying metrics.

---

# 13\. Dashboard Metrics

Keep KPI cards extremely simple.

```
Tasks completed

128
↑ 18.4%

vs. previous period
```

Recommended metrics:

- Tasks completed
- Tasks running
- Success rate
- Average execution time
- Tokens / usage
- Cost
- Human interventions

Avoid dashboards filled with 12–20 KPI cards.

**4–6 important metrics are usually enough.**

---

# 14\. Agent Activity Timeline

This is one of the most important components.

Use a timeline rather than a generic activity table.

```
10:42
● Agent started task

10:43
✓ Retrieved 18 documents

10:44
✓ Analyzed competitor data

10:46
⚠ Human approval required

10:48
→ Waiting for approval
```

Use subtle color and icons.

Don't make every event a colorful badge.

---

# 15\. Agent Status

AI agents require more than simple loading indicators.

Use meaningful states:

```
Idle
Planning
Running
Thinking
Waiting
Needs approval
Completed
Failed
Paused
```

Each state should have:

- icon
- label
- optional description
- appropriate semantic color

Example:

```
◌ Planning
Determining the next actions…
```

This creates transparency and trust.

---

# 16\. Agent Chat / Command Interface

The command area should feel like a **workspace**, not a messaging app.

Recommended:

```
┌──────────────────────────────────────────────┐
│ Ask the agent to analyze the Q3 report...    │
│                                              │
│                                      ↑ Send  │
└──────────────────────────────────────────────┘

Attach   Tools   Model   Context
```

Keep the input prominent.

Use keyboard-first interactions:

```
Enter       Send
Shift+Enter New line
⌘K          Command palette
Esc         Close
```

---

# 17\. AI Response Design

Avoid giant text bubbles.

Instead:

```
Agent
────────────────────────────────

I've analyzed the dataset and found
three significant anomalies.

### Key findings

1. Revenue increased 18%
2. Conversion dropped 4.2%
3. Mobile traffic accounts for 61%

[View analysis] [Create report]
```

The response should support **actions**, not just conversation.

---

# 18\. Tool Execution UI

When an agent uses tools, show it clearly.

Example:

```
● Agent is working

┌─────────────────────────────────┐
│ ✓ Search web                    │
│ ✓ Retrieved 24 results          │
│ ● Analyzing documents           │
│ ○ Generate summary              │
└─────────────────────────────────┘
```

The user should never wonder:

> "Is the AI stuck?"

---

# 19\. Human-in-the-Loop

Approval states deserve strong visual hierarchy.

Example:

```
┌────────────────────────────────────────┐
│ Approval required                      │
│                                        │
│ The agent wants to send this email.    │
│                                        │
│ ┌────────────────────────────────────┐ │
│ │ To: client@example.com              │ │
│ │ Subject: Project update             │ │
│ └────────────────────────────────────┘ │
│                                        │
│ [Reject]                 [Approve]     │
└────────────────────────────────────────┘
```

Use warning/amber sparingly.

Approval should feel important without feeling like an error.

---

# 20\. Tables

AI dashboards frequently need tables.

Use:

- 44–48px row height
- subtle row dividers
- right-aligned numerical values
- compact status indicators
- sticky header for large datasets

Avoid heavy borders around every cell.

Better:

```
─────────────────────────────────────────
Agent       Status       Tasks     Usage
─────────────────────────────────────────
Research    ● Running      24      $12.40
Writer      ● Idle         18       $8.20
Analyst     ● Waiting      31      $21.10
─────────────────────────────────────────
```

---

# 21\. Buttons

Create a clear hierarchy.

### Primary

```
Background: Primary
Text: White
```

Example:

**Run agent**

### Secondary

```
Background: transparent
Border: subtle
```

Example:

**View logs**

### Tertiary

No border.

Example:

**Cancel**

### Destructive

Use red only for destructive actions.

Example:

**Delete agent**

Never make destructive actions visually compete with the primary CTA.

---

# 22\. Inputs

Inputs should be extremely clean.

```
Label

┌───────────────────────────────┐
│ Enter agent name              │
└───────────────────────────────┘

Helper text
```

Focus state:

```
border: primary
box-shadow: 0 0 0 3px primary/12%
```

Avoid thick glowing focus rings.

---

# 23\. Icons

Use one icon family throughout the application.

Good choices:

- Lucide
- Phosphor
- Heroicons

Recommended stroke:

```
1.5–2px
```

Don't mix filled and outlined icon styles randomly.

Icons should support text—not replace it when meaning isn't obvious.

---

# 24\. Data Visualization

Charts should use the same design language.

Avoid rainbow charts.

### Preferred palette

```
Primary     #635BFF
Blue        #2E90FA
Green       #12B76A
Amber       #F79009
Red         #F04438
Gray        #98A2B3
```

For dark mode, slightly brighten them.

Use **one dominant color + semantic colors** rather than six competing colors.

---

# 25\. Gradients

Gradients should be an accent, not the foundation.

Good:

```
background:
  radial-gradient(
    circle at top right,
    rgba(99, 91, 255, .10),
    transparent 40%
  );
```

Bad:

```
Entire dashboard = purple/blue gradient
```

Use gradients primarily for:

- AI identity
- Empty states
- Hero areas
- Marketing-style overview sections

---

# 26\. Shadows

### Light

Use very soft shadows:

```
box-shadow:
  0 1px 2px rgba(16, 24, 40, .04),
  0 4px 12px rgba(16, 24, 40, .04);
```

### Dark

Prefer borders.

If a shadow is needed:

```
box-shadow:
  0 12px 30px rgba(0, 0, 0, .25);
```

Never make every card float.

---

# 27\. Motion

Animation should communicate state.

Recommended durations:

```
Micro interaction     120–160ms
Hover                 150ms
Panel transition      200–250ms
Modal                 200–300ms
Complex transition    300–400ms
```

Use easing:

```
ease-out
cubic-bezier(.2,.8,.2,1)
```

Good animations:

- Agent status transition
- Progress updates
- Panel opening
- Task completion
- Streaming AI response

Avoid:

- constant pulsing
- excessive bouncing
- animated gradients everywhere
- unnecessary page transitions

---

# 28\. Empty States

Never show an empty white/gray box.

Instead:

```
        ✦

No agents yet

Create your first AI agent to automate
research, analysis, and repetitive tasks.

        [Create agent]
```

Keep the illustration subtle.

---

# 29\. Loading States

Prefer skeletons over generic spinners.

Example:

```
┌────────────────────────────┐
│ █████████████              │
│ ████████                   │
│                            │
│ █████████████████          │
└────────────────────────────┘
```

For agent execution, use meaningful activity:

```
● Searching documents…
● Analyzing results…
```

A spinner alone doesn't communicate enough.

---

# 30\. Accessibility

Target **WCAG AA** as the baseline.

Important rules:

- Body text should maintain sufficient contrast.
- Never use color as the only status indicator.
- Keyboard navigation must work.
- Focus states must be visible.
- Interactive targets should be approximately **40px+**.
- Don't rely on tiny text for critical information.
- Respect `prefers-reduced-motion`.

For dark mode especially, don't use overly dim gray text.

A common mistake is:

```
#555
```

on:

```
#0B0D10
```

It looks stylish but becomes difficult to read.

---

# 31\. Light vs Dark Theme Philosophy

The two themes should feel like the **same product**, not two different products.

### Light mode

Should feel:

> Clean · bright · analytical · professional

### Dark mode

Should feel:

> Focused · sophisticated · calm · immersive

Use the same:

- spacing
- typography
- component shapes
- iconography
- layout
- semantic colors

Only surfaces, contrast levels, and accent brightness should substantially change.

---

# 32\. Recommended Design Tokens

Build the entire UI around semantic tokens rather than hard-coded colors.

```
:root {
  --bg: #F7F8FA;
  --surface: #FFFFFF;
  --surface-subtle: #F1F3F5;
  --border: #E5E7EB;

  --text-primary: #111827;
  --text-secondary: #667085;
  --text-muted: #98A2B3;

  --primary: #635BFF;
  --primary-hover: #5548E8;

  --success: #12B76A;
  --warning: #F79009;
  --error: #F04438;
  --info: #2E90FA;
}
```

Dark theme:

```
[data-theme="dark"] {
  --bg: #0B0D10;
  --surface: #11151A;
  --surface-subtle: #1B2128;
  --border: #252B33;

  --text-primary: #F2F4F7;
  --text-secondary: #98A2B3;
  --text-muted: #667085;

  --primary: #8B7CFF;
  --primary-hover: #A196FF;

  --success: #32D583;
  --warning: #FDB022;
  --error: #F97066;
  --info: #53B1FD;
}
```

The key is that components consume:

```
var(--surface)
var(--text-primary)
var(--border)
var(--primary)
```

rather than individual hex values.

---

# 33\. Component Architecture

Create a reusable design system around:

```
Layout
├── AppShell
├── Sidebar
├── TopBar
└── ContentArea

Navigation
├── NavItem
├── Breadcrumb
└── CommandPalette

Agent
├── AgentCard
├── AgentAvatar
├── AgentStatus
├── AgentSelector
├── AgentActivity
└── AgentTimeline

AI
├── AIMessage
├── ToolExecution
├── ThinkingState
├── AIInsight
└── ApprovalRequest

Data
├── MetricCard
├── DataTable
├── Chart
├── Progress
└── Timeline

Forms
├── Input
├── Select
├── Checkbox
├── Toggle
└── Button

Feedback
├── Toast
├── Alert
├── EmptyState
├── Skeleton
└── ErrorState
```

This prevents every screen from developing its own visual language.

---

# 34\. The "Premium AI" Rule

The interface should **not constantly remind users that it is AI**.

Avoid:

```
✨ AI MAGIC
🤖 INTELLIGENT ENGINE
⚡ AI POWERED
```

everywhere.

Instead, communicate intelligence through behavior:

```
Agent understands context
Agent shows its progress
Agent uses tools
Agent explains results
Agent asks for approval
Agent remembers relevant information
Agent recovers from errors
```

That feels considerably more sophisticated.

---

# 35\. Final Visual Formula

For the overall product, I'd use this formula:

```
             MODERN AI DASHBOARD

        ┌──────────────────────────┐
        │       Calm surfaces      │
        │                          │
        │   Strong typography      │
        │                          │
        │  ┌──────┐   ┌────────┐  │
        │  │ Data │   │ Agent  │  │
        │  └──────┘   └────────┘  │
        │                          │
        │   Subtle purple accent   │
        │                          │
        │   Minimal borders        │
        │   Restrained shadows     │
        │   Clear AI states        │
        │                          │
        └──────────────────────────┘
```

### Design principles to keep on the wall

1. **Neutral first, color second.**
2. **Hierarchy before decoration.**
3. **Show what the agent is doing.**
4. **Every state should be understandable.**
5. **Dark mode is designed, not inverted.**
6. **Use one accent color consistently.**
7. **Prefer borders over heavy shadows.**
8. **Use whitespace to reduce cognitive load.**
9. **Animation communicates state, never decoration.**
10. **The AI should feel intelligent through interaction—not neon visuals.**

