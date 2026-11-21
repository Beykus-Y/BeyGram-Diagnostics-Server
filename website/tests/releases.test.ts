import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ANDROID_RELEASES_URL,
  fetchAndroidReleases,
  fetchOtherPlatformsAvailability,
  formatBytes,
  parseChangelogSections,
  selectStableAndroidReleases,
  type GitHubRelease,
} from '../src/lib/releases.ts';

function createMemoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return Array.from(map.keys())[index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(key, value);
    },
  };
}

function makeRelease(overrides: Partial<GitHubRelease>): GitHubRelease {
  return {
    id: 1,
    tag_name: 'v0.0.6.1',
    name: 'BeyGram 0.0.6.1',
    body: '## Главное\n- Плеер-трансформер\n<!-- TECHNICAL_CHANGELOG -->\n* PR #1',
    draft: false,
    prerelease: false,
    published_at: '2026-11-19T14:50:59Z',
    html_url: 'https://github.com/Beykus-Y/BeyGram/releases/tag/v0.0.6.1',
    assets: [
      {
        name: 'BeyGram-0.0.6.1-prod-release.apk',
        size: 115693666,
        browser_download_url:
          'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.6.1/BeyGram-0.0.6.1-prod-release.apk',
      },
      {
        name: 'BeyGram-stable-update.json',
        size: 220,
        browser_download_url:
          'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.6.1/BeyGram-stable-update.json',
      },
    ],
    ...overrides,
  };
}

test('selectStableAndroidReleases ignores prereleases, drafts, and non-APK assets', () => {
  const releases: GitHubRelease[] = [
    makeRelease({
      id: 10,
      tag_name: 'dev-645',
      name: 'DEV dev-645',
      prerelease: true,
      assets: [
        {
          name: 'BeyGram-dev-645.apk',
          size: 100000000,
          browser_download_url: 'https://github.com/Beykus-Y/BeyGram/releases/download/dev-645/BeyGram-dev-645.apk',
        },
      ],
    }),
    makeRelease({
      id: 9,
      tag_name: 'v0.0.6.2-draft',
      draft: true,
    }),
    makeRelease({
      id: 8,
      tag_name: 'v0.0.6.1',
    }),
    makeRelease({
      id: 7,
      tag_name: 'v0.0.6.0',
      name: 'BeyGram 0.0.6.0',
      published_at: '2026-11-17T12:31:26Z',
      html_url: 'https://github.com/Beykus-Y/BeyGram/releases/tag/v0.0.6.0',
      assets: [
        {
          name: 'BeyGram-0.0.6.0-prod-release.apk',
          size: 114194530,
          browser_download_url:
            'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.6.0/BeyGram-0.0.6.0-prod-release.apk',
        },
      ],
    }),
  ];

  const { latest, previous } = selectStableAndroidReleases(releases);
  assert.ok(latest);
  assert.equal(latest.tagName, 'v0.0.6.1');
  assert.equal(latest.apks.length, 1);
  assert.equal(latest.primaryApk.name, 'BeyGram-0.0.6.1-prod-release.apk');
  assert.equal(previous.length, 1);
  assert.equal(previous[0].tagName, 'v0.0.6.0');
});

test('selectStableAndroidReleases sorts multiple ABI APKs meaningfully', () => {
  const rel = makeRelease({
    assets: [
      {
        name: 'BeyGram-0.0.7.0-armeabi-v7a.apk',
        size: 80000000,
        browser_download_url: 'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.7.0/armeabi-v7a.apk',
      },
      {
        name: 'BeyGram-0.0.7.0-arm64-v8a.apk',
        size: 90000000,
        browser_download_url: 'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.7.0/arm64-v8a.apk',
      },
      {
        name: 'BeyGram-0.0.7.0-universal.apk',
        size: 130000000,
        browser_download_url: 'https://github.com/Beykus-Y/BeyGram/releases/download/v0.0.7.0/universal.apk',
      },
    ],
  });

  const { latest } = selectStableAndroidReleases([rel]);
  assert.ok(latest);
  assert.equal(latest.apks.length, 3);
  assert.equal(latest.primaryApk.name, 'BeyGram-0.0.7.0-universal.apk');
  assert.match(latest.apks[1].abiLabel, /ARM64/);
  assert.match(latest.apks[2].abiLabel, /ARMv7/);
});

test('parseChangelogSections strips technical PR list and keeps user sections', () => {
  const body = [
    '# BeyGram 0.0.6.1',
    '',
    '## Главное',
    '- Плеер-трансформер',
    '- Форумы 2.0',
    '',
    '### Плеер',
    '- Жест раскрытия',
    '',
    '<!-- TECHNICAL_CHANGELOG -->',
    "## What's Changed",
    '* Internal PR by @user',
  ].join('\n');

  const parsed = parseChangelogSections(body);
  assert.equal(parsed.hasMore, true);
  assert.equal(parsed.sections.length, 2);
  assert.equal(parsed.sections[0].title, 'Главное');
  assert.deepEqual(parsed.sections[0].items, ['Плеер-трансформер', 'Форумы 2.0']);
  assert.equal(parsed.sections[1].title, 'Плеер');
});

test('fetchAndroidReleases handles empty releases list honestly', async () => {
  const storage = createMemoryStorage();
  const state = await fetchAndroidReleases({
    storage,
    fetchImpl: async () => new Response(JSON.stringify([]), { status: 200 }),
  });

  assert.equal(state.status, 'empty');
  assert.equal(state.latest, null);
  assert.equal(state.releasesPageUrl, ANDROID_RELEASES_URL);
});

test('fetchAndroidReleases handles rate limit 403 and falls back to stale cache when present', async () => {
  const storage = createMemoryStorage();
  const now = 1_700_000_000_000;

  // Seed fresh cache
  const first = await fetchAndroidReleases({
    storage,
    now,
    fetchImpl: async () => new Response(JSON.stringify([makeRelease({})]), { status: 200 }),
  });
  assert.equal(first.status, 'ready');
  assert.equal(first.fromCache, false);

  // Within TTL: does not call fetch
  let called = false;
  const cachedHit = await fetchAndroidReleases({
    storage,
    now: now + 60_000,
    fetchImpl: async () => {
      called = true;
      return new Response('[]', { status: 200 });
    },
  });
  assert.equal(called, false);
  assert.equal(cachedHit.fromCache, true);
  assert.equal(cachedHit.stale, false);

  // After TTL expires, API returns 403 rate limit -> falls back to stale cache
  const staleFallback = await fetchAndroidReleases({
    storage,
    now: now + 20 * 60_000,
    fetchImpl: async () => new Response(JSON.stringify({ message: 'rate limit' }), { status: 403 }),
  });
  assert.equal(staleFallback.status, 'ready');
  assert.equal(staleFallback.stale, true);
  assert.equal(staleFallback.latest?.tagName, 'v0.0.6.1');
});

test('fetchAndroidReleases returns error state on API failure with empty cache', async () => {
  const storage = createMemoryStorage();
  const state = await fetchAndroidReleases({
    storage,
    fetchImpl: async () => new Response('rate limit', { status: 429 }),
  });

  assert.equal(state.status, 'error');
  assert.equal(state.latest, null);
  assert.match(state.errorMessage ?? '', /лимит/i);
});

test('fetchOtherPlatformsAvailability returns unavailable when no releases exist', async () => {
  const storage = createMemoryStorage();
  const platforms = await fetchOtherPlatformsAvailability({
    storage,
    fetchImpl: async () => new Response(JSON.stringify([]), { status: 200 }),
  });

  assert.equal(platforms.length, 2);
  assert.equal(platforms[0].id, 'ios');
  assert.equal(platforms[0].available, false);
  assert.equal(platforms[1].id, 'windows');
  assert.equal(platforms[1].available, false);
});

test('formatBytes formats MB cleanly in Russian locale', () => {
  assert.equal(formatBytes(115693666), '110,3 МБ');
  assert.equal(formatBytes(0), '—');
});
