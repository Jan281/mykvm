import type { EdgeAnchor, EdgeLink, EdgeSide, LayoutState, Screen } from './types'

export const EDGE_SIDES: EdgeSide[] = ['top', 'right', 'bottom', 'left']

/** Horizontal sides run along x, vertical sides along y. */
export function sideRunsHorizontally(side: EdgeSide) {
  return side === 'top' || side === 'bottom'
}

export function oppositeSide(side: EdgeSide): EdgeSide {
  switch (side) {
    case 'left':
      return 'right'
    case 'right':
      return 'left'
    case 'top':
      return 'bottom'
    case 'bottom':
      return 'top'
  }
}

/** Screens overlap when they share area, which means they cannot share an edge. */
function screensOverlap(a: Screen, b: Screen) {
  return (
    a.x < b.x + b.width &&
    b.x < a.x + a.width &&
    a.y < b.y + b.height &&
    b.y < a.y + a.height
  )
}

const EDGE_TOLERANCE = 80

function touchingSide(local: Screen, remote: Screen): EdgeSide | null {
  const near = (a: number, b: number) => Math.abs(a - b) <= EDGE_TOLERANCE
  const overlaps = (a1: number, a2: number, b1: number, b2: number) =>
    Math.min(a2, b2) - Math.max(a1, b1) > 0

  const vertical = overlaps(local.y, local.y + local.height, remote.y, remote.y + remote.height)
  const horizontal = overlaps(local.x, local.x + local.width, remote.x, remote.x + remote.width)

  if (near(local.x + local.width, remote.x) && vertical) return 'right'
  if (near(local.x, remote.x + remote.width) && vertical) return 'left'
  if (near(local.y + local.height, remote.y) && horizontal) return 'bottom'
  if (near(local.y, remote.y + remote.height) && horizontal) return 'top'
  return null
}

/**
 * The stretch two adjacent screens share along `side`, as a fraction of each
 * screen's own side. Mirrors `geometric_spans` on the Rust side — the seeded
 * wiring has to behave exactly like the geometry it replaces.
 */
function geometricSpans(local: Screen, remote: Screen, side: EdgeSide) {
  const horizontal = sideRunsHorizontally(side)
  const localStart = horizontal ? local.x : local.y
  const localExtent = horizontal ? local.width : local.height
  const remoteStart = horizontal ? remote.x : remote.y
  const remoteExtent = horizontal ? remote.width : remote.height

  const overlapStart = Math.max(localStart, remoteStart)
  const overlapEnd = Math.min(localStart + localExtent, remoteStart + remoteExtent)
  if (overlapEnd <= overlapStart) return null

  const span = (start: number, extent: number) => ({
    start: clamp01((overlapStart - start) / Math.max(extent, 1)),
    end: clamp01((overlapEnd - start) / Math.max(extent, 1)),
  })

  return { local: span(localStart, localExtent), remote: span(remoteStart, remoteExtent) }
}

export function clamp01(value: number) {
  return Math.min(1, Math.max(0, value))
}

/**
 * Derives the wiring a screen arrangement implies, which is what the editor
 * opens with when a layout has never been wired by hand.
 */
export function edgeLinksFromGeometry(layout: LayoutState): EdgeLink[] {
  const localDevice = layout.devices.find((device) => device.role === 'local')
  if (!localDevice) return []

  const links: EdgeLink[] = []
  for (const device of layout.devices) {
    if (device.role === 'local') continue
    for (const localScreen of localDevice.screens) {
      for (const remoteScreen of device.screens) {
        if (screensOverlap(localScreen, remoteScreen)) continue
        const side = touchingSide(localScreen, remoteScreen)
        if (!side) continue
        const spans = geometricSpans(localScreen, remoteScreen, side)
        if (!spans) continue

        links.push({
          id: `geometry:${localScreen.id}:${side}:${remoteScreen.id}`,
          a: {
            deviceId: localDevice.id,
            screenId: localScreen.id,
            side,
            ...spans.local,
          },
          b: {
            deviceId: device.id,
            screenId: remoteScreen.id,
            side: oppositeSide(side),
            ...spans.remote,
          },
        })
      }
    }
  }

  return links
}

/** The wiring in force: what the user drew, or what their arrangement implies. */
export function effectiveEdgeLinks(layout: LayoutState): EdgeLink[] {
  return layout.edgeLinks ?? edgeLinksFromGeometry(layout)
}

export function anchorMatchesScreen(anchor: EdgeAnchor, screenId: string, side: EdgeSide) {
  return anchor.screenId === screenId && anchor.side === side
}

export function linkTouches(link: EdgeLink, screenId: string, side: EdgeSide) {
  return anchorMatchesScreen(link.a, screenId, side) || anchorMatchesScreen(link.b, screenId, side)
}

/**
 * The cut points already present on one side of a screen: every boundary of
 * every link attached to it. These are what the editor draws as segments.
 */
export function sideBoundaries(
  links: EdgeLink[],
  screenId: string,
  side: EdgeSide,
  extraCuts: number[] = [],
): number[] {
  const points = new Set<number>([0, 1])
  for (const cut of extraCuts) {
    points.add(clamp01(cut))
  }
  for (const link of links) {
    for (const anchor of [link.a, link.b]) {
      if (!anchorMatchesScreen(anchor, screenId, side)) continue
      points.add(clamp01(Math.min(anchor.start, anchor.end)))
      points.add(clamp01(Math.max(anchor.start, anchor.end)))
    }
  }
  return [...points].sort((a, b) => a - b)
}

export interface SideSegment {
  start: number
  end: number
  link: EdgeLink | null
}

/** One side of a screen, cut into the stretches the links define. */
export function sideSegments(
  links: EdgeLink[],
  screenId: string,
  side: EdgeSide,
  extraCuts: number[] = [],
): SideSegment[] {
  const boundaries = sideBoundaries(links, screenId, side, extraCuts)
  const segments: SideSegment[] = []

  for (let index = 0; index < boundaries.length - 1; index += 1) {
    const start = boundaries[index]
    const end = boundaries[index + 1]
    if (end - start < 1e-6) continue
    const middle = (start + end) / 2
    const link =
      links.find((candidate) =>
        [candidate.a, candidate.b].some(
          (anchor) =>
            anchorMatchesScreen(anchor, screenId, side) &&
            middle >= Math.min(anchor.start, anchor.end) &&
            middle <= Math.max(anchor.start, anchor.end),
        ),
      ) ?? null
    segments.push({ start, end, link })
  }

  return segments.length > 0 ? segments : [{ start: 0, end: 1, link: null }]
}

/**
 * Cuts a side at `fraction`, so the two halves can be wired separately.
 *
 * A cut only adds a boundary; it never touches an existing link. Splitting a
 * stretch that is already wired would have to guess which half keeps the
 * destination, so the editor makes the user unlink first.
 */
export function splitSide(links: EdgeLink[], screenId: string, side: EdgeSide, fraction: number) {
  const covering = links.find((link) =>
    [link.a, link.b].some(
      (anchor) =>
        anchorMatchesScreen(anchor, screenId, side) &&
        fraction > Math.min(anchor.start, anchor.end) &&
        fraction < Math.max(anchor.start, anchor.end),
    ),
  )
  return { cut: clamp01(fraction), blocked: Boolean(covering) }
}

/**
 * The other local screen that makes an edge unusable, if there is one.
 *
 * Mirrors `linux_edge_blocked_by` in the backend, which in turn mirrors the
 * rule stated in xdg-desktop-portal-kde: a pointer barrier is allowed only if
 * it fills one screen edge that no other screen touches. Showing this in the
 * editor is the whole reason to draw edges — otherwise the only symptom is a
 * cursor that quietly hops to the neighbouring monitor.
 */
export function edgeBlockedBy(
  screen: Screen,
  side: EdgeSide,
  localScreens: Screen[],
): Screen | null {
  const horizontal = sideRunsHorizontally(side)
  const line =
    side === 'top'
      ? screen.y
      : side === 'bottom'
        ? screen.y + screen.height
        : side === 'left'
          ? screen.x
          : screen.x + screen.width
  const spanStart = horizontal ? screen.x : screen.y
  const spanEnd = spanStart + (horizontal ? screen.width : screen.height) - 1

  return (
    localScreens.find((other) => {
      if (other.id === screen.id) return false
      const near = horizontal ? other.y : other.x
      const extent = horizontal ? other.height : other.width
      if (line !== near && line !== near + extent) return false
      const otherStart = horizontal ? other.x : other.y
      const otherEnd = otherStart + (horizontal ? other.width : other.height) - 1
      return spanStart <= otherEnd && otherStart <= spanEnd
    }) ?? null
  )
}

export function makeLinkId() {
  return `link-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

/** Removes every link attached to a screen side stretch. */
export function removeLink(links: EdgeLink[], linkId: string) {
  return links.filter((link) => link.id !== linkId)
}

/**
 * Wires two stretches together, dropping anything that already claimed either
 * of them — one stretch can only lead to one place.
 */
export function connect(links: EdgeLink[], a: EdgeAnchor, b: EdgeAnchor): EdgeLink[] {
  const overlaps = (anchor: EdgeAnchor, other: EdgeAnchor) =>
    anchor.screenId === other.screenId &&
    anchor.side === other.side &&
    Math.min(anchor.end, other.end) - Math.max(anchor.start, other.start) > 1e-6

  const kept = links.filter(
    (link) =>
      ![link.a, link.b].some((anchor) => overlaps(anchor, a) || overlaps(anchor, b)),
  )
  return [...kept, { id: makeLinkId(), a, b }]
}

export function describeAnchor(anchor: EdgeAnchor, screenName: string, sideLabel: string) {
  const whole = anchor.start <= 1e-6 && anchor.end >= 1 - 1e-6
  if (whole) return `${screenName} · ${sideLabel}`
  return `${screenName} · ${sideLabel} ${Math.round(anchor.start * 100)}–${Math.round(
    anchor.end * 100,
  )}%`
}
