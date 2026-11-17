import { Version } from '../../../wailsjs/go/wails/Handler'

// getVersion — версия программы из Go (заодно проверка связи фронт ↔ Go).
export function getVersion(): Promise<string> {
  return Version()
}
