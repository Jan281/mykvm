export type Platform = 'windows' | 'macos' | 'unknown'

export type MachineRole = 'unset' | 'server' | 'client'

export type AppLanguage = 'cn' | 'en' | 'de'

export type ThemeMode = 'system' | 'dark' | 'light'

export type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'trace'

export type TransportPortMode = 'auto' | 'fixed'

export type ModifierTarget = 'control' | 'alt' | 'meta' | 'same'

export interface ModifierMap {
  control: ModifierTarget
  alt: ModifierTarget
  meta: ModifierTarget
}

export interface ScreenSwitchHotkeys {
  left: string
  right: string
  up: string
  down: string
}

export interface PairedController {
  id: string
  name: string
  host: string
  ip: string
  transportPublicKey: string
  protocolVersion: number
  clusterId: string
  pairedAtMs: number
}

export interface Screen {
  id: string
  deviceId: string
  name: string
  x: number
  y: number
  width: number
  height: number
  scale: number
  /** How large the screen is drawn in the layout, relative to its resolution. */
  boardScale?: number
  isPrimary: boolean
}

export type EdgeSide = 'left' | 'right' | 'top' | 'bottom'

/**
 * A stretch of one side of one screen. `start`/`end` are fractions of that
 * side — 0 is the left end of a horizontal side, the top end of a vertical one
 * — so a link survives a resolution change.
 */
export interface EdgeAnchor {
  deviceId: string
  screenId: string
  side: EdgeSide
  start: number
  end: number
}

/** Two edge stretches wired together: leaving one lands on the other. */
export interface EdgeLink {
  id: string
  a: EdgeAnchor
  b: EdgeAnchor
}

export interface Device {
  id: string
  name: string
  platform: Platform
  host: string
  transportPort: number
  quicPort: number
  transportPublicKey: string
  protocolVersion: number
  color: string
  online: boolean
  inputReady: boolean
  upgrading?: boolean
  role: 'local' | 'server' | 'client'
  source?: 'detected' | 'manual'
  screens: Screen[]
}

export interface LayoutState {
  devices: Device[]
  activeDeviceId: string
  selectedScreenId: string
  inputMode: 'control' | 'receive'
  machineRole: MachineRole
  clusterId: string
  pairSecret: string
  pairedControllers: PairedController[]
  clipboardSync: boolean
  fileTransferEnabled: boolean
  language: AppLanguage
  themeMode: ThemeMode
  performanceMonitor: boolean
  startMinimized: boolean
  transportPortMode: TransportPortMode
  transportPort: number
  quicPort: number
  modifierRemap: boolean
  modifierMap: ModifierMap
  edgeSwitchHotkey: string
  screenSwitchHotkeys: ScreenSwitchHotkeys
  /**
   * Explicit edge wiring. `null` means this layout predates the edge editor and
   * still routes off where the screens sit; once it is an array the user has
   * taken over, and only what is linked hands over — an empty array included.
   */
  edgeLinks: EdgeLink[] | null
  /** How much detail goes into the log file. 'debug' enables per-event traces. */
  logLevel: LogLevel
}
