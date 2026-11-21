export interface GitHubAsset {
  name: string;
  size: number;
  browser_download_url: string;
  content_type?: string;
}

export interface GitHubRelease {
  id: number;
  tag_name: string;
  name: string | null;
  body: string | null;
  draft: boolean;
  prerelease: boolean;
  published_at: string | null;
  html_url: string;
  assets: GitHubAsset[];
}

export interface ApkAsset {
  name: string;
  size: number;
  sizeLabel: string;
  downloadUrl: string;
  abiLabel: string;
  priority: number;
}

export interface ChangelogSection {
  title: string;
  items: string[];
}

export interface StableAndroidRelease {
  tagName: string;
  title: string;
  publishedAt: string | null;
  dateLabel: string;
  htmlUrl: string;
  apks: ApkAsset[];
  primaryApk: ApkAsset;
  changelog: ChangelogSection[];
  hasMoreChangelog: boolean;
}

export type ReleaseLoadStatus = 'loading' | 'ready' | 'empty' | 'error';

export interface AndroidReleasesState {
  status: ReleaseLoadStatus;
  latest: StableAndroidRelease | null;
  previous: StableAndroidRelease[];
  fromCache: boolean;
  stale: boolean;
  errorMessage: string | null;
  releasesPageUrl: string;
}

export interface PlatformAvailability {
  id: 'android' | 'ios' | 'windows';
  name: string;
  available: boolean;
  statusLabel: string;
  description: string;
  repoUrl: string;
  downloadUrl: string | null;
  versionLabel: string | null;
}

export const ANDROID_REPO = 'Beykus-Y/BeyGram';
export const IOS_REPO = 'Beykus-Y/BeyGram-iOS';
export const WINDOWS_REPO = 'Beykus-Y/BeyGram-Windows';

export const ANDROID_RELEASES_URL = `https://github.com/${ANDROID_REPO}/releases`;
export const ANDROID_LATEST_URL = `https://github.com/${ANDROID_REPO}/releases/latest`;
export const IOS_REPO_URL = `https://github.com/${IOS_REPO}`;
export const WINDOWS_REPO_URL = `https://github.com/${WINDOWS_REPO}`;

const CACHE_KEY_ANDROID = 'beygram-android-releases-v1';
const CACHE_KEY_PLATFORMS = 'beygram-other-platforms-v1';
const ANDROID_CACHE_TTL_MS = 10 * 60 * 1000;
const OTHER_PLATFORMS_CACHE_TTL_MS = 30 * 60 * 1000;

interface CachedPayload<T> {
  fetchedAt: number;
  data: T;
}

function isSafeHttpsUrl(url: unknown): url is string {
  if (typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '—';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) {
    return `${mb.toFixed(1).replace('.', ',')} МБ`;
  }
  const kb = bytes / 1024;
  return `${Math.round(kb)} КБ`;
}

export function formatReleaseDate(isoDate: string | null): string {
  if (!isoDate) return 'Дата не указана';
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) return 'Дата не указана';
  return new Intl.DateTimeFormat('ru-RU', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  }).format(date);
}

export function detectApkAbi(filename: string): { label: string; priority: number } {
  const lower = filename.toLowerCase();
  if (lower.includes('universal')) {
    return { label: 'Universal APK (все архитектуры)', priority: 0 };
  }
  if (lower.includes('arm64-v8a') || lower.includes('arm64')) {
    return { label: 'ARM64 (современные Android-устройства)', priority: 1 };
  }
  if (lower.includes('armeabi-v7a') || lower.includes('armv7')) {
    return { label: 'ARMv7 (32-bit)', priority: 2 };
  }
  if (lower.includes('x86_64')) {
    return { label: 'x86_64', priority: 3 };
  }
  if (lower.includes('x86')) {
    return { label: 'x86', priority: 4 };
  }
  return { label: 'Android APK (ARM64)', priority: 1 };
}

export function extractApkAssets(assets: GitHubAsset[]): ApkAsset[] {
  return assets
    .filter((asset) => {
      if (!asset || typeof asset.name !== 'string') return false;
      const lower = asset.name.toLowerCase();
      return lower.endsWith('.apk') && isSafeHttpsUrl(asset.browser_download_url);
    })
    .map((asset) => {
      const abi = detectApkAbi(asset.name);
      return {
        name: asset.name,
        size: typeof asset.size === 'number' ? asset.size : 0,
        sizeLabel: formatBytes(asset.size),
        downloadUrl: asset.browser_download_url,
        abiLabel: abi.label,
        priority: abi.priority,
      };
    })
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));
}

export function parseChangelogSections(body: string | null): {
  sections: ChangelogSection[];
  hasMore: boolean;
} {
  if (!body || typeof body !== 'string') {
    return { sections: [], hasMore: false };
  }

  let userPart = body;
  let hasMore = false;

  const techMarkers = ['<!-- TECHNICAL_CHANGELOG -->', "\n## What's Changed", '\n**Full Changelog**'];
  for (const marker of techMarkers) {
    const idx = userPart.indexOf(marker);
    if (idx !== -1) {
      userPart = userPart.slice(0, idx);
      hasMore = true;
    }
  }

  const lines = userPart.split(/\r?\n/);
  const sections: ChangelogSection[] = [];
  let current: ChangelogSection | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    // Skip top-level release title like "# BeyGram 0.0.6.1"
    if (/^#\s+/.test(line)) continue;

    const headingMatch = line.match(/^#{2,3}\s+(.+)$/);
    if (headingMatch) {
      current = { title: headingMatch[1].trim(), items: [] };
      sections.push(current);
      continue;
    }

    const bulletMatch = line.match(/^[-*]\s+(.+)$/);
    if (bulletMatch) {
      if (!current) {
        current = { title: 'Изменения', items: [] };
        sections.push(current);
      }
      current.items.push(bulletMatch[1].trim());
    }
  }

  const nonEmpty = sections.filter((s) => s.items.length > 0);
  return { sections: nonEmpty, hasMore };
}

export function selectStableAndroidReleases(
  rawReleases: GitHubRelease[],
  previousLimit = 5
): { latest: StableAndroidRelease | null; previous: StableAndroidRelease[] } {
  if (!Array.isArray(rawReleases)) {
    return { latest: null, previous: [] };
  }

  const stableWithApks: StableAndroidRelease[] = [];

  for (const rel of rawReleases) {
    if (!rel || rel.draft || rel.prerelease) continue;
    const apks = extractApkAssets(Array.isArray(rel.assets) ? rel.assets : []);
    if (apks.length === 0) continue;

    const { sections, hasMore } = parseChangelogSections(rel.body);
    const htmlUrl = isSafeHttpsUrl(rel.html_url) ? rel.html_url : ANDROID_RELEASES_URL;

    stableWithApks.push({
      tagName: rel.tag_name,
      title: (rel.name && rel.name.trim()) || rel.tag_name,
      publishedAt: rel.published_at,
      dateLabel: formatReleaseDate(rel.published_at),
      htmlUrl,
      apks,
      primaryApk: apks[0],
      changelog: sections,
      hasMoreChangelog: hasMore,
    });
  }

  if (stableWithApks.length === 0) {
    return { latest: null, previous: [] };
  }

  return {
    latest: stableWithApks[0],
    previous: stableWithApks.slice(1, 1 + previousLimit),
  };
}

function readCache<T>(storage: Storage | undefined, key: string): CachedPayload<T> | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedPayload<T>;
    if (!parsed || typeof parsed.fetchedAt !== 'number' || parsed.data === undefined) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function writeCache<T>(storage: Storage | undefined, key: string, data: T, now: number): void {
  if (!storage) return;
  try {
    const payload: CachedPayload<T> = { fetchedAt: now, data };
    storage.setItem(key, JSON.stringify(payload));
  } catch {
    // Ignore storage quota / privacy mode errors
  }
}

function getDefaultStorage(): Storage | undefined {
  try {
    return typeof window !== 'undefined' ? window.localStorage : undefined;
  } catch {
    return undefined;
  }
}

export async function fetchAndroidReleases(options?: {
  fetchImpl?: typeof fetch;
  storage?: Storage;
  now?: number;
}): Promise<AndroidReleasesState> {
  const fetchImpl = options?.fetchImpl ?? fetch;
  const storage = options?.storage ?? getDefaultStorage();
  const now = options?.now ?? Date.now();

  const cached = readCache<GitHubRelease[]>(storage, CACHE_KEY_ANDROID);
  if (cached && now - cached.fetchedAt < ANDROID_CACHE_TTL_MS) {
    const { latest, previous } = selectStableAndroidReleases(cached.data);
    return {
      status: latest ? 'ready' : 'empty',
      latest,
      previous,
      fromCache: true,
      stale: false,
      errorMessage: null,
      releasesPageUrl: ANDROID_RELEASES_URL,
    };
  }

  try {
    const response = await fetchImpl(
      `https://api.github.com/repos/${ANDROID_REPO}/releases?per_page=15`,
      {
        headers: {
          Accept: 'application/vnd.github+json',
        },
      }
    );

    if (!response.ok) {
      const isRateLimit = response.status === 403 || response.status === 429;
      throw new Error(
        isRateLimit
          ? 'Превышен лимит запросов к GitHub API.'
          : `GitHub API вернул статус ${response.status}.`
      );
    }

    const raw = (await response.json()) as GitHubRelease[];
    if (!Array.isArray(raw)) {
      throw new Error('Некорректный ответ GitHub API.');
    }

    writeCache(storage, CACHE_KEY_ANDROID, raw, now);
    const { latest, previous } = selectStableAndroidReleases(raw);

    return {
      status: latest ? 'ready' : 'empty',
      latest,
      previous,
      fromCache: false,
      stale: false,
      errorMessage: null,
      releasesPageUrl: ANDROID_RELEASES_URL,
    };
  } catch (err) {
    if (cached) {
      const { latest, previous } = selectStableAndroidReleases(cached.data);
      if (latest) {
        return {
          status: 'ready',
          latest,
          previous,
          fromCache: true,
          stale: true,
          errorMessage: err instanceof Error ? err.message : 'Не удалось обновить данные о релизах.',
          releasesPageUrl: ANDROID_RELEASES_URL,
        };
      }
    }

    return {
      status: 'error',
      latest: null,
      previous: [],
      fromCache: false,
      stale: false,
      errorMessage:
        err instanceof Error
          ? err.message
          : 'Не удалось получить список релизов с GitHub.',
      releasesPageUrl: ANDROID_RELEASES_URL,
    };
  }
}

export const DEFAULT_OTHER_PLATFORMS: PlatformAvailability[] = [
  {
    id: 'ios',
    name: 'iOS',
    available: false,
    statusLabel: 'Пока недоступно · в разработке',
    description:
      'Клиент для iOS (ветка 0.0.1 DEV на базе Telegram-iOS). Публичных релизов и TestFlight-сборок пока нет.',
    repoUrl: IOS_REPO_URL,
    downloadUrl: null,
    versionLabel: null,
  },
  {
    id: 'windows',
    name: 'Windows',
    available: false,
    statusLabel: 'Пока недоступно · в разработке',
    description:
      'Настольный клиент для Windows находится на раннем этапе разработки. Готовых установщиков в релизах пока нет.',
    repoUrl: WINDOWS_REPO_URL,
    downloadUrl: null,
    versionLabel: null,
  },
];

function findSupportedInstallerAsset(
  releases: GitHubRelease[],
  extensions: string[]
): { release: GitHubRelease; asset: GitHubAsset } | null {
  for (const rel of releases) {
    if (!rel || rel.draft || rel.prerelease || !Array.isArray(rel.assets)) continue;
    for (const asset of rel.assets) {
      if (!asset || typeof asset.name !== 'string') continue;
      const lower = asset.name.toLowerCase();
      if (
        extensions.some((ext) => lower.endsWith(ext)) &&
        isSafeHttpsUrl(asset.browser_download_url)
      ) {
        return { release: rel, asset };
      }
    }
  }
  return null;
}

export async function fetchOtherPlatformsAvailability(options?: {
  fetchImpl?: typeof fetch;
  storage?: Storage;
  now?: number;
}): Promise<PlatformAvailability[]> {
  const fetchImpl = options?.fetchImpl ?? fetch;
  const storage = options?.storage ?? getDefaultStorage();
  const now = options?.now ?? Date.now();

  const cached = readCache<PlatformAvailability[]>(storage, CACHE_KEY_PLATFORMS);
  if (cached && now - cached.fetchedAt < OTHER_PLATFORMS_CACHE_TTL_MS) {
    return cached.data;
  }

  const checkRepo = async (
    base: PlatformAvailability,
    repo: string,
    extensions: string[]
  ): Promise<PlatformAvailability> => {
    try {
      const res = await fetchImpl(`https://api.github.com/repos/${repo}/releases?per_page=5`, {
        headers: { Accept: 'application/vnd.github+json' },
      });
      if (!res.ok) return base;
      const raw = (await res.json()) as GitHubRelease[];
      if (!Array.isArray(raw)) return base;
      const found = findSupportedInstallerAsset(raw, extensions);
      if (!found) return base;
      return {
        ...base,
        available: true,
        statusLabel: `Доступно · ${found.release.tag_name}`,
        downloadUrl: found.asset.browser_download_url,
        versionLabel: found.release.tag_name,
      };
    } catch {
      return base;
    }
  };

  const result = await Promise.all([
    checkRepo(DEFAULT_OTHER_PLATFORMS[0], IOS_REPO, ['.ipa']),
    checkRepo(DEFAULT_OTHER_PLATFORMS[1], WINDOWS_REPO, ['.exe', '.msi', '.msix', '.msixbundle']),
  ]);

  writeCache(storage, CACHE_KEY_PLATFORMS, result, now);
  return result;
}
