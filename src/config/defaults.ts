import pkg from '../../package.json';
import { SystemSettings } from '../types';

const pkgVersion = String(pkg.version || '0.0.0').trim();

export const DEFAULT_SETTINGS: SystemSettings = {
  transparency: 70,
  backdropBlur: 16,
  reducedMotion: false,
  autoUpdate: false,
  version: pkgVersion,
  hostname: '',
  adminEmail: '',
  timezone: 'UTC',
  maxMessageSizeMb: 50,
  relayConcurrency: 20,
  rateLimitPerHour: 500,
  spamThreshold: 6.0,
  colorTheme: 'cyan',
  logoStyle: '3d_glass',
  customLogo: '',
};
