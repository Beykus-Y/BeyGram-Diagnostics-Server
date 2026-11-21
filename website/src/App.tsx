import { useEffect, useState } from 'react';
import {
  ANDROID_LATEST_URL,
  ANDROID_RELEASES_URL,
  DEFAULT_OTHER_PLATFORMS,
  fetchAndroidReleases,
  fetchOtherPlatformsAvailability,
  type AndroidReleasesState,
  type PlatformAvailability,
} from './lib/releases.ts';

type Screen = 'chats' | 'dialog' | 'accounts' | 'proxy' | 'theme';
type Account = 0 | 1 | 2;
type Player = 'circle' | 'voice' | 'music';

const COLORS = ['#1f5bff', '#c2593f', '#5b4bc4', '#2f8a7b', '#a9731d', '#3a78c2', '#b0476e'];
const COLOR_LABELS = ['Фирменный синий', 'Терракота', 'Индиго', 'Бирюза', 'Охра', 'Небо', 'Роза'];
const GITHUB = 'https://github.com/Beykus-Y/BeyGram';
const DIAGNOSTICS_GITHUB = 'https://github.com/Beykus-Y/BeyGram-Diagnostics-Server';
const CHANNEL = 'https://t.me/beygram_client';
const LOGO = '/logo.webp';

const ACCOUNTS = [
  { name: 'Личный', detail: 'Алиса · личный', avatar: 'А', count: 8, color: '#5b4bc4' },
  { name: 'Рабочий', detail: 'Алиса · рабочий', avatar: 'Р', count: 13, color: '#2f8a7b' },
  { name: 'Тестовый', detail: 'бета-сборки', avatar: 'Т', count: 0, color: '#c2593f' },
] as const;

const CHATSETS = [
  [
    { name: 'Мария', message: 'Да, смотри', time: '09:41', unread: 2, color: '#c2593f' },
    { name: 'Дизайн-чат', message: 'Скинули варианты акцента', time: '09:12', unread: 5, color: '#5b4bc4' },
    { name: 'Бета-тестеры', message: 'Новая сборка доступна', time: '08:50', unread: 1, color: '#2f8a7b' },
    { name: 'Папа', message: 'Позвони вечером', time: 'вчера', unread: 0, color: '#a9731d' },
    { name: 'Книжный клуб', message: 'Голосовое · 0:42', time: 'вчера', unread: 0, color: '#3a78c2' },
  ],
  [
    { name: 'Команда', message: 'Посмотрим исправление сегодня', time: '10:10', unread: 3, color: '#3a78c2' },
    { name: 'Разработка', message: 'Сборка прошла проверку', time: '09:54', unread: 7, color: '#5b4bc4' },
    { name: 'Проект', message: 'Обновили документацию', time: 'вчера', unread: 3, color: '#2f8a7b' },
  ],
  [
    { name: 'Тестовый чат', message: 'Проверка уведомлений', time: '11:12', unread: 0, color: '#c2593f' },
    { name: 'Черновики', message: 'Демонстрационные данные', time: 'вчера', unread: 0, color: '#a9731d' },
  ],
];

const SCREENS: { id: Screen; title: string; text: string }[] = [
  { id: 'chats', title: 'Чаты', text: 'Порядок и закрепления, аватары и счётчики непрочитанного.' },
  { id: 'dialog', title: 'Диалог', text: 'Ответы, медиа и сообщения — с оформлением на ваш вкус.' },
  { id: 'accounts', title: 'Аккаунты', text: 'Личный, рабочий и тестовый — в едином интерфейсе.' },
  { id: 'proxy', title: 'Прокси', text: 'Ручные подключения и Mihomo с автоматическим выбором узла.' },
  { id: 'theme', title: 'Оформление', text: 'Акцент, радиус пузырей и размеры текста меняют макет вживую.' },
];

const NODES = [
  { name: 'Нидерланды · 01', ping: 48 },
  { name: 'Германия · 02', ping: 92 },
  { name: 'Финляндия · 03', ping: 41 },
  { name: 'Казахстан · 04', ping: 131 },
];

const PHASES = ['Подключено', 'Связь пропала', 'Проверка узлов', 'Переключение', 'Подключено снова'];

const IMPLEMENTED_FEATURES = [
  {
    tag: 'ЧАТЫ И ФОРУМЫ',
    title: 'Списки, папки и форумы 2.0',
    text: 'Папки чатов, глобальный поиск с фильтрами, три режима навигации по темам форума, лента «Все сообщения» и обновлённые закреплённые сообщения.',
  },
  {
    tag: 'АККАУНТЫ',
    title: 'Несколько профилей рядом',
    text: 'Быстрое переключение между аккаунтами в одном приложении с полной изоляцией локальных данных и сессий TDLib.',
  },
  {
    tag: 'СЕТЬ И ПРОКСИ',
    title: 'Встроенный Mihomo и MTProto',
    text: 'Поддержка HTTPS YAML-подписок Mihomo с локальным SOCKS на 127.0.0.1 без системного VPN-профиля, проверка задержки и автопереключение узлов.',
  },
  {
    tag: 'МЕДИА И ПЛЕЕР',
    title: 'Плеер-трансформер и музыка',
    text: 'Плавный переход мини-плеера в полный плеер и очередь, просмотр фото, видео, голосовых, альбомов, локальных списков и Яндекс Музыки.',
  },
  {
    tag: 'УВЕДОМЛЕНИЯ',
    title: 'Без Google Play Services',
    text: 'Прямое подключение TDLib и опциональная фоновая служба, а также поддержка веб-компаньона BG Push.',
  },
  {
    tag: 'ПРИВАТНОСТЬ И ОБНОВЛЕНИЯ',
    title: 'Контроль и ручные отчёты',
    text: 'Режим невидимки, ручная проверка обновлений Stable с проверкой SHA-256 и подписи, диагностические отчёты только по явной кнопке.',
  },
];

const FAQ_ITEMS = [
  {
    q: 'Это официальный клиент Telegram?',
    a: 'Нет. BeyGram — независимый клиент на базе TDLib с открытым исходным кодом (GNU GPL v3). Проект не аффилирован с Telegram.',
  },
  {
    q: 'Чем открытое бета-тестирование (Stable) отличается от DEV-сборок?',
    a: 'На этой странице публикуются только проверенные стабильные релизы (Stable) с пометкой без pre-release. DEV-сборки на GitHub предназначены для внутренней отладки и не рекомендуются для повседневного общения.',
  },
  {
    q: 'Сохранятся ли чаты и аккаунты при обновлении APK?',
    a: 'Да, если вы устанавливаете новую Stable-версию поверх предыдущей Stable-сборки (один и тот же application ID com.beykus.beygram и релизная подпись). Не удаляйте приложение перед обновлением — это сотрёт локальную сессию.',
  },
  {
    q: 'Нужны ли Google-сервисы (GMS / Firebase) для уведомлений?',
    a: 'Нет. Уведомления работают через прямое подключение TDLib и необязательную фоновую службу. На некоторых прошивках Android стоит разрешить работу без оптимизации батареи.',
  },
  {
    q: 'Как сообщить об ошибке или предложить улучшение?',
    a: 'Через экран «Настройки → Диагностика» в приложении (если у вас есть доступ к отчётности), в Telegram-канале @beygram_client или через GitHub Issues.',
  },
];

function BtnLink({
  href,
  children,
  primary = false,
  external = false,
  download,
}: {
  href: string;
  children: React.ReactNode;
  primary?: boolean;
  external?: boolean;
  download?: boolean;
}) {
  return (
    <a
      className={'button ' + (primary ? 'primary' : 'outline')}
      href={href}
      download={download}
      {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
    >
      {children}
    </a>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}

function Phone({
  screen,
  account,
  accent,
  radius,
  textSize,
  onScreen,
  onAccount,
  interactive = true,
  light = false,
  chatListRevision = 0,
}: {
  screen: Screen;
  account: Account;
  accent: string;
  radius: number;
  textSize: number;
  onScreen?: (s: Screen) => void;
  onAccount?: (a: Account) => void;
  interactive?: boolean;
  light?: boolean;
  chatListRevision?: number;
}) {
  const [activeChat, setActiveChat] = useState(false);
  useEffect(() => setActiveChat(false), [screen, account, chatListRevision]);
  const safeSwitch = (s: Screen) => {
    if (!interactive) return;
    if (s === 'chats') setActiveChat(false);
    onScreen?.(s);
  };
  return (
    <div
      className={'device ' + (light ? 'device-light' : '')}
      style={
        {
          '--phone-accent': accent,
          '--bubble-radius': radius + 'px',
          '--bubble-size': textSize + 'px',
        } as React.CSSProperties
      }
    >
      <div className="speaker" />
      <div className="statusbar">
        <b>9:41</b>
        <span>▣ ▣ ▣ 5G</span>
      </div>
      {screen === 'dialog' || activeChat ? (
        <>
          <div className="phone-head">
            <button
              type="button"
              className="phone-back"
              onClick={() => (activeChat ? setActiveChat(false) : safeSwitch('chats'))}
              aria-label="Вернуться к чатам"
            >
              ←
            </button>
            <span className="avatar peach">М</span>
            <span>
              <b>Мария</b>
              <small>в сети</small>
            </span>
            <span className="head-dots">⋮</span>
          </div>
          <div className="messages">
            <div className="pin">Закреплённое сообщение · Созвон в 19:00</div>
            <div className="daylabel">Сегодня</div>
            <div className="message incoming">Привет! Ты уже сменила тему?</div>
            <div className="message outgoing">Да! Акцент, радиус, шрифт — всё под себя ✓✓</div>
            <div className="message incoming">А прокси работает без VPN?</div>
            <div className="message outgoing">Локальный SOCKS, системный VPN не нужен ✓✓</div>
            <div className="message incoming">Красиво. А углы пузырей можно сделать мягче?</div>
            <div className="message outgoing">Можно: от 4 до 24 dp ✓✓</div>
          </div>
          <div className="compose">
            Сообщение <span>➤</span>
          </div>
        </>
      ) : screen === 'chats' ? (
        <>
          <div className="phone-head phone-chats-head">
            <b>Чаты</b>
            <button
              type="button"
              onClick={() => safeSwitch('accounts')}
              aria-label="Переключить аккаунт"
              className="avatar blue"
            >
              {ACCOUNTS[account].avatar}
            </button>
          </div>
          <div className="search">Поиск</div>
          <div className="chatlist">
            {CHATSETS[account].map((chat) => (
              <button type="button" key={chat.name} className="chat-row" onClick={() => setActiveChat(true)}>
                <span className="avatar" style={{ background: chat.color }}>
                  {chat.name[0]}
                </span>
                <span className="chat-info">
                  <b>{chat.name}</b>
                  <small>{chat.message}</small>
                </span>
                <span className="chat-meta">
                  <small>{chat.time}</small>
                  {chat.unread > 0 && <strong>{chat.unread}</strong>}
                </span>
              </button>
            ))}
          </div>
        </>
      ) : screen === 'accounts' ? (
        <>
          <div className="phone-head">
            <b>Аккаунты</b>
          </div>
          <div className="phone-page">
            <p>Выберите аккаунт</p>
            {ACCOUNTS.map((a, i) => (
              <button
                type="button"
                key={a.name}
                className={'phone-option ' + (account === i ? 'selected' : '')}
                onClick={() => interactive && onAccount?.(i as Account)}
              >
                <span className="avatar" style={{ background: a.color }}>
                  {a.avatar}
                </span>
                <span>
                  <b>{a.name}</b>
                  <small>{a.detail}</small>
                </span>
                <span>›</span>
              </button>
            ))}
          </div>
        </>
      ) : screen === 'proxy' ? (
        <>
          <div className="phone-head">
            <b>Подключение</b>
          </div>
          <div className="phone-page">
            <p className="connected">● Прокси подключён</p>
            <strong>Автоматический выбор</strong>
            <small className="hint">Демонстрация доступных узлов</small>
            {NODES.map((node, i) => (
              <div className="phone-option" key={node.name}>
                <span className="dot" />
                <span>
                  <b>{node.name}</b>
                  <small>{node.ping} мс</small>
                </span>
                {i === 0 ? '✓' : ''}
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          <div className="phone-head">
            <b>Оформление</b>
          </div>
          <div className="phone-page">
            <strong>Ваш стиль</strong>
            <p>Графитовая тема</p>
            <div className="theme-preview">
              <div className="message incoming">Так будет выглядеть чат</div>
              <div className="message outgoing">Всё под вашим контролем ✓</div>
            </div>
            <small className="hint">Попробуйте изменить акцент на сайте</small>
          </div>
        </>
      )}
      <nav className="phone-tabs" aria-label="Демонстрационное меню">
        {(
          [
            ['chats', 'Чаты', '◉'],
            ['accounts', 'Аккаунты', '◎'],
            ['proxy', 'Прокси', '⇄'],
            ['theme', 'Тема', '◇'],
          ] as const
        ).map(([id, name, glyph]) => (
          <button type="button" className={screen === id ? 'on' : ''} key={id} onClick={() => safeSwitch(id)}>
            <span>{glyph}</span>
            {name}
          </button>
        ))}
      </nav>
      <div className="home-bar" />
    </div>
  );
}

function ProxyDemo() {
  const [phase, setPhase] = useState(0);
  const [running, setRunning] = useState(false);
  useEffect(() => {
    if (!running) return;
    const timeouts = [
      setTimeout(() => setPhase(2), 1300),
      setTimeout(() => setPhase(3), 2900),
      setTimeout(() => {
        setPhase(4);
        setRunning(false);
      }, 3900),
    ];
    return () => timeouts.forEach(clearTimeout);
  }, [running]);
  const start = () => {
    if (running) return;
    setPhase(1);
    setRunning(true);
  };
  const notes = [
    'Telegram подключён через выбранный узел.',
    'Соединение не отвечает. Ждём перед повторной проверкой.',
    'Проверяем доступность узлов.',
    'Найден доступный узел с меньшей задержкой.',
    'Симуляция завершена. Доступность не гарантируется.',
  ];
  return (
    <div className="proxy-showcase">
      <div className="proxy-panel">
        <div className="proxy-top">
          <b>Подключение к Telegram</b>
          <span className={'connection ' + (running ? 'waiting' : '')}>
            {phase === 0 || phase === 4 ? '● Подключено' : '◌ Проверка'}
          </span>
        </div>
        <div className="pills">
          <span>MTProto</span>
          <span>SOCKS5</span>
          <span>HTTP</span>
          <b>Mihomo</b>
        </div>
        <div className="node-list">
          {NODES.map((n, i) => {
            const active = phase === 0 ? i === 0 : phase >= 3 ? i === 2 : false;
            return (
              <div key={n.name} className={'node ' + (active ? 'active' : '')}>
                <span>
                  <i className={active ? 'green' : ''} />
                  {n.name}
                </span>
                <small>{phase > 0 && i === 0 ? 'таймаут' : phase === 2 ? 'проверка…' : n.ping + ' мс'}</small>
              </div>
            );
          })}
        </div>
        <p className="proxy-note">{notes[phase]}</p>
        <button type="button" className="proxy-trigger" onClick={start} disabled={running}>
          {running ? 'Идёт симуляция…' : phase === 4 ? 'Повторить симуляцию' : 'Смоделировать сбой'}
        </button>
      </div>
      <div className="proxy-steps">
        <Eyebrow>ЧТО ПРОИСХОДИТ</Eyebrow>
        {PHASES.map((p, i) => (
          <div className={'step ' + (i === phase ? 'now' : i < phase ? 'done' : '')} key={p}>
            <span>{i < phase ? '✓' : String(i + 1).padStart(2, '0')}</span>
            <strong>{p}</strong>
          </div>
        ))}
        <small>Интерактивный сценарий, без реальных запросов к серверам и подключения к Telegram.</small>
      </div>
    </div>
  );
}

function MediaDemo() {
  const [camera, setCamera] = useState(false);
  const [fov, setFov] = useState(false);
  const [recording, setRecording] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [player, setPlayer] = useState<Player | null>(null);
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    if (!recording && !player) return;
    const id = window.setInterval(() => {
      if (recording) setElapsed((v) => (v >= 12 ? (setRecording(false), 12) : Math.min(12, v + 0.1)));
      if (player) setProgress((v) => (v >= 1 ? (setPlayer(null), 1) : Math.min(1, v + 0.0125)));
    }, 100);
    return () => window.clearInterval(id);
  }, [recording, player]);
  const play = (name: Player) => {
    setPlayer((p) => (p === name ? null : name));
    setProgress(0);
  };
  return (
    <div className="media-grid">
      <div className="recorder">
        <div className="mono recorder-top">
          <span>Видеосообщения · макет</span>
          <span>0:{String(Math.floor(elapsed)).padStart(2, '0')}</span>
        </div>
        <div
          className="camera-ring"
          style={{ background: `conic-gradient(var(--onbrand) ${(elapsed / 12) * 100}%,rgba(255,255,255,.2) 0)` }}
        >
          <div className={'camera-face ' + (fov ? 'zoom' : '')}>
            <div>
              Демо-кадр
              <br />
              {camera ? 'основная' : 'фронтальная'} камера
              <br />
              {fov ? 'узкий' : 'широкий'} угол
            </div>
          </div>
        </div>
        <div className="rec-controls">
          <button type="button" onClick={() => setCamera((v) => !v)}>
            ⟲ Камера
          </button>
          <button
            type="button"
            className="record"
            onClick={() => {
              setRecording((v) => !v);
              if (!recording) setElapsed(0);
            }}
          >
            <span className={'red-dot ' + (recording ? 'active' : '')} />
            {recording ? 'Остановить' : 'Записать'}
          </button>
          <button type="button" onClick={() => setFov((v) => !v)}>
            Угол: {fov ? 'узкий' : 'широкий'}
          </button>
        </div>
        <small>Демонстрация поведения — без доступа к камере и микрофону.</small>
      </div>
      <div className="media-feed">
        <div className="media-feed-head mono">
          Лента чата <span>демо-данные</span>
        </div>
        <div className="circle-line">
          <button
            type="button"
            className="video-circle"
            onClick={() => play('circle')}
            style={{ '--progress': (player === 'circle' ? progress : 0) * 100 + '%' } as React.CSSProperties}
          >
            {player === 'circle' ? 'Ⅱ' : '▶'}
          </button>
          <div>
            <b>Видеосообщение</b>
            <small>{player === 'circle' ? Math.floor(progress * 12) : 0} / 0:12 · нажмите для просмотра</small>
          </div>
        </div>
        <div className="voice-line">
          <button type="button" onClick={() => play('voice')} aria-label="Воспроизвести голосовое">
            {player === 'voice' ? 'Ⅱ' : '▶'}
          </button>
          <div className="wave">
            {Array.from({ length: 26 }, (_, i) => (
              <i
                key={i}
                style={{
                  height: 20 + ((i * 47) % 72) + '%',
                  background: player === 'voice' && i < progress * 26 ? 'var(--brand)' : 'var(--line)',
                }}
              />
            ))}
          </div>
          <small>0:08</small>
        </div>
        <div className="media-pairs">
          <div>фото</div>
          <div>
            видео <span>0:24</span>
          </div>
        </div>
        <div className="music-line">
          <span className="album">♫</span>
          <div>
            <b>Аудиофайл</b>
            <div className="audio-progress">
              <i style={{ width: player === 'music' ? progress * 100 + '%' : '0%' }} />
            </div>
          </div>
          <button type="button" onClick={() => play('music')} aria-label="Воспроизвести аудио">
            {player === 'music' ? 'Ⅱ' : '▶'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [dark, setDark] = useState(() => {
    try {
      return localStorage.getItem('beygram-theme') !== 'light';
    } catch {
      return true;
    }
  });
  const [accentIndex, setAccentIndex] = useState(0);
  const [screen, setScreen] = useState<Screen>('chats');
  const [account, setAccount] = useState<Account>(0);
  const [radius, setRadius] = useState(16);
  const [textSize, setTextSize] = useState(15);
  const [menu, setMenu] = useState(false);
  const [scroll, setScroll] = useState(0);
  const [chatListRevision, setChatListRevision] = useState(0);
  const [showFullChangelog, setShowFullChangelog] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const [releasesState, setReleasesState] = useState<AndroidReleasesState>({
    status: 'loading',
    latest: null,
    previous: [],
    fromCache: false,
    stale: false,
    errorMessage: null,
    releasesPageUrl: ANDROID_RELEASES_URL,
  });
  const [otherPlatforms, setOtherPlatforms] = useState<PlatformAvailability[]>(DEFAULT_OTHER_PLATFORMS);

  const accent = COLORS[accentIndex];

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    try {
      localStorage.setItem('beygram-theme', dark ? 'dark' : 'light');
    } catch {
      // ignore
    }
  }, [dark]);

  useEffect(() => {
    const rgb = [1, 3, 5]
      .map((i) => parseInt(accent.slice(i, i + 2), 16) / 255)
      .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    const lum = rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
    document.documentElement.style.setProperty('--brand', accent);
    document.documentElement.style.setProperty('--onbrand', lum > 0.4 ? '#111' : '#fff');
  }, [accent]);

  useEffect(() => {
    const update = () => {
      const doc = document.documentElement;
      setScroll((doc.scrollTop / Math.max(1, doc.scrollHeight - doc.clientHeight)) * 100);
    };
    window.addEventListener('scroll', update, { passive: true });
    update();
    return () => window.removeEventListener('scroll', update);
  }, []);

  useEffect(() => {
    let active = true;
    fetchAndroidReleases().then((state) => {
      if (active) setReleasesState(state);
    });
    fetchOtherPlatformsAvailability().then((platforms) => {
      if (active) setOtherPlatforms(platforms);
    });
    return () => {
      active = false;
    };
  }, []);

  const latest = releasesState.latest;
  const primaryApk = latest?.primaryApk ?? null;
  const visibleChangelog = latest
    ? showFullChangelog
      ? latest.changelog
      : latest.changelog.slice(0, 2)
    : [];

  return (
    <>
      <div className="scroll-progress" style={{ width: scroll + '%' }} />
      <header className="site-header">
        <div className="wrap header-wrap">
          <a className="wordmark" href="#top">
            <img
              src={LOGO}
              alt="Логотип BeyGram"
              onError={(e) => {
                e.currentTarget.style.display = 'none';
              }}
            />
            <span>BeyGram</span>
          </a>
          <nav className="desktop-nav" aria-label="Основная навигация">
            <a href="#download">Скачать</a>
            <a href="#features">Возможности</a>
            <a href="#demo">Демо</a>
            <a href="#platforms">Платформы</a>
            <a href="#obt">ОБТ</a>
            <a href="#faq">FAQ</a>
          </nav>
          <div className="header-tools">
            <button
              type="button"
              className="round"
              onClick={() => setDark((v) => !v)}
              aria-label={dark ? 'Включить светлую тему' : 'Включить тёмную тему'}
            >
              {dark ? '☀' : '☾'}
            </button>
            <a href="#download" className="nav-cta">
              Скачать BeyGram
            </a>
            <button
              type="button"
              className="round mobile-toggle"
              onClick={() => setMenu((v) => !v)}
              aria-label={menu ? 'Закрыть меню' : 'Открыть меню'}
              aria-expanded={menu}
            >
              {menu ? '✕' : '☰'}
            </button>
          </div>
        </div>
        {menu && (
          <nav className="mobile-nav" aria-label="Мобильная навигация">
            {[
              ['#download', 'Скачать BeyGram'],
              ['#features', 'Возможности'],
              ['#demo', 'Интерактивное демо'],
              ['#platforms', 'Платформы'],
              ['#obt', 'Установка и ОБТ'],
              ['#faq', 'FAQ и поддержка'],
            ].map(([href, label]) => (
              <a key={href} href={href} onClick={() => setMenu(false)}>
                {label}
              </a>
            ))}
          </nav>
        )}
      </header>

      <main>
        <section id="top" className="hero wrap">
          <div className="hero-copy">
            <Eyebrow>
              <span className="live-dot" /> Открытое бета-тестирование · клиент Telegram для Android
            </Eyebrow>
            <h1>
              Telegram,
              <br />
              <em>настроенный</em>
              <br />
              под вас.
            </h1>
            <p className="intro">
              Свои цвета и пузыри, несколько аккаунтов в одном приложении и встроенный прокси Mihomo.
              Независимый клиент с открытым исходным кодом (GPL v3).
            </p>
            <div className="hero-actions" aria-live="polite">
              {primaryApk ? (
                <BtnLink primary href={primaryApk.downloadUrl} download>
                  Скачать BeyGram · {latest?.tagName}
                </BtnLink>
              ) : (
                <BtnLink primary href="#download">
                  Скачать BeyGram
                </BtnLink>
              )}
              <BtnLink href="#download">
                {primaryApk ? `Подробнее о ${latest?.tagName}` : 'Релизы и платформы'}
              </BtnLink>
            </div>
            <p className="caption mono">
              {releasesState.status === 'loading' && 'Проверяем актуальный стабильный релиз на GitHub…'}
              {releasesState.status === 'ready' &&
                latest &&
                primaryApk &&
                `Стабильная сборка ${latest.tagName} · ${latest.dateLabel} · ${primaryApk.sizeLabel} · Android 10+`}
              {(releasesState.status === 'error' || releasesState.status === 'empty') &&
                'Откройте раздел загрузок или GitHub Releases для получения актуального APK.'}
            </p>
            <div className="color-controls">
              <span>Попробуйте цвет →</span>
              {COLORS.map((c, i) => (
                <button
                  type="button"
                  key={c}
                  title={COLOR_LABELS[i]}
                  aria-label={COLOR_LABELS[i]}
                  aria-pressed={accentIndex === i}
                  onClick={() => setAccentIndex(i)}
                  className={accentIndex === i ? 'selected' : ''}
                  style={{ background: c }}
                />
              ))}
            </div>
          </div>
          <div className="hero-phones">
            <div className="hero-phone-back">
              <Phone screen="chats" account={0} accent={accent} radius={radius} textSize={textSize} interactive={false} light />
            </div>
            <div className="hero-phone-front">
              <Phone screen="dialog" account={0} accent={accent} radius={radius} textSize={textSize} interactive={false} />
            </div>
          </div>
        </section>

        <div className="wrap">
          <p className="mock-note mono">
            Иллюстрация интерфейса. Все демонстрационные чаты и имена на сайте вымышлены.
          </p>
        </div>

        <section className="download-section" id="download">
          <div className="wrap section-pad">
            <Eyebrow>ЗАГРУЗКА · ОТКРЫТОЕ БЕТА-ТЕСТИРОВАНИЕ</Eyebrow>
            <h2>
              Актуальный <em>стабильный релиз.</em>
            </h2>
            <p className="section-lead">
              На странице публикуются только стабильные сборки из GitHub Releases. Экспериментальные DEV-сборки сюда не попадают.
            </p>

            <div className="release-grid" aria-live="polite">
              <div className="release-card">
                {releasesState.status === 'loading' && (
                  <div className="release-state">
                    <Eyebrow>GITHUB RELEASES</Eyebrow>
                    <h3>Загружаем информацию о релизе…</h3>
                    <p>Получаем актуальный стабильный APK из репозитория Beykus-Y/BeyGram.</p>
                    <BtnLink href={ANDROID_LATEST_URL} external>
                      Открыть GitHub Releases ↗
                    </BtnLink>
                  </div>
                )}

                {(releasesState.status === 'error' || releasesState.status === 'empty') && (
                  <div className="release-state">
                    <Eyebrow>GITHUB RELEASES · FALLBACK</Eyebrow>
                    <h3>
                      {releasesState.status === 'empty'
                        ? 'Стабильные APK-релизы пока не найдены'
                        : 'Не удалось автоматически загрузить релиз'}
                    </h3>
                    <p>
                      {releasesState.errorMessage ??
                        'Список стабильных сборок временно недоступен. Вы можете скачать актуальный APK напрямую со страницы релизов на GitHub.'}
                    </p>
                    <div className="release-actions">
                      <BtnLink primary href={ANDROID_LATEST_URL} external>
                        Скачать на GitHub Releases ↗
                      </BtnLink>
                      <BtnLink href={ANDROID_RELEASES_URL} external>
                        Все версии ↗
                      </BtnLink>
                    </div>
                  </div>
                )}

                {releasesState.status === 'ready' && latest && primaryApk && (
                  <>
                    <div className="release-head">
                      <div>
                        <span className="release-badge">STABLE · ОБТ</span>
                        <h3>{latest.title}</h3>
                      </div>
                      <div className="release-meta mono">
                        <span>Версия: {latest.tagName}</span>
                        <span>Дата: {latest.dateLabel}</span>
                        <span>Размер: {primaryApk.sizeLabel}</span>
                      </div>
                    </div>

                    {releasesState.stale && (
                      <p className="stale-note mono">
                        Показаны сохранённые данные о релизе (GitHub API временно ограничил запросы).
                      </p>
                    )}

                    <div className="release-actions">
                      <BtnLink primary href={primaryApk.downloadUrl} download>
                        Скачать APK ({primaryApk.sizeLabel})
                      </BtnLink>
                      <BtnLink href={latest.htmlUrl} external>
                        Релиз на GitHub ↗
                      </BtnLink>
                    </div>

                    <div className="apk-assets">
                      <span className="mono apk-file-name">
                        Файл: {primaryApk.name} · {primaryApk.abiLabel}
                      </span>
                      {latest.apks.length > 1 && (
                        <div className="abi-list">
                          {latest.apks.map((apk) => (
                            <a key={apk.name} href={apk.downloadUrl} download className="abi-chip">
                              <b>{apk.abiLabel}</b>
                              <span className="mono">
                                {apk.name} · {apk.sizeLabel}
                              </span>
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>

              <div className="previous-card">
                <Eyebrow>ПРЕДЫДУЩИЕ СТАБИЛЬНЫЕ ВЕРСИИ</Eyebrow>
                {releasesState.status === 'ready' && releasesState.previous.length > 0 ? (
                  <ul className="previous-list">
                    {releasesState.previous.map((rel) => (
                      <li key={rel.tagName} className="previous-item">
                        <div>
                          <b>{rel.tagName}</b>
                          <small className="mono">
                            {rel.dateLabel} · {rel.primaryApk.sizeLabel}
                          </small>
                        </div>
                        <div className="previous-links">
                          <a href={rel.primaryApk.downloadUrl} download className="mono">
                            APK ↓
                          </a>
                          <a href={rel.htmlUrl} target="_blank" rel="noopener noreferrer" className="mono">
                            GitHub ↗
                          </a>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="previous-empty">
                    Архив стабильных версий и их примечания доступны в{' '}
                    <a href={ANDROID_RELEASES_URL} target="_blank" rel="noopener noreferrer">
                      GitHub Releases ↗
                    </a>
                    .
                  </p>
                )}
              </div>
            </div>

            {latest && latest.changelog.length > 0 && (
              <div className="changelog-box" id="changelog">
                <div className="changelog-head">
                  <div>
                    <Eyebrow>ЧТО НОВОГО В {latest.tagName}</Eyebrow>
                    <h3>Примечания к выпуску</h3>
                  </div>
                  <div className="changelog-controls">
                    {latest.changelog.length > 2 && (
                      <button
                        type="button"
                        className="button outline"
                        onClick={() => setShowFullChangelog((v) => !v)}
                      >
                        {showFullChangelog ? 'Свернуть список' : `Показать все разделы (${latest.changelog.length})`}
                      </button>
                    )}
                    <BtnLink href={latest.htmlUrl} external>
                      Полный changelog ↗
                    </BtnLink>
                  </div>
                </div>
                <div className="changelog-sections">
                  {visibleChangelog.map((sec) => (
                    <div key={sec.title} className="changelog-section">
                      <h4>{sec.title}</h4>
                      <ul>
                        {sec.items.map((item, idx) => (
                          <li key={idx}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="wrap section-pad" id="platforms">
          <Eyebrow>ПЛАТФОРМЫ</Eyebrow>
          <h2>
            Доступность <em>по системам.</em>
          </h2>
          <div className="platforms-grid">
            <div className="platform-card platform-ready">
              <div className="platform-top">
                <b>Android</b>
                <span className="status-pill ready">ОБТ · Доступно</span>
              </div>
              <p>
                Основной клиент на Kotlin, Jetpack Compose и TDLib. Требуется Android 10 (API 29) и выше, архитектура ARM64.
              </p>
              <div className="platform-foot">
                {primaryApk ? (
                  <a href={primaryApk.downloadUrl} download className="mono">
                    Скачать {latest?.tagName} ({primaryApk.sizeLabel}) ↓
                  </a>
                ) : (
                  <a href={ANDROID_RELEASES_URL} target="_blank" rel="noopener noreferrer" className="mono">
                    Релизы на GitHub ↗
                  </a>
                )}
              </div>
            </div>

            {otherPlatforms.map((plat) => (
              <div key={plat.id} className={'platform-card ' + (plat.available ? 'platform-ready' : '')}>
                <div className="platform-top">
                  <b>{plat.name}</b>
                  <span className={'status-pill ' + (plat.available ? 'ready' : 'dev')}>{plat.statusLabel}</span>
                </div>
                <p>{plat.description}</p>
                <div className="platform-foot">
                  {plat.available && plat.downloadUrl ? (
                    <a href={plat.downloadUrl} download className="mono">
                      Скачать {plat.versionLabel} ↓
                    </a>
                  ) : (
                    <a href={plat.repoUrl} target="_blank" rel="noopener noreferrer" className="mono">
                      Репозиторий на GitHub ↗
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="features-section" id="features">
          <div className="wrap section-pad">
            <Eyebrow>ВОЗМОЖНОСТИ СТАБИЛЬНОЙ ВЕРСИИ</Eyebrow>
            <h2>
              Что уже работает <em>в BeyGram.</em>
            </h2>
            <p className="section-lead">
              Только функции, реально реализованные в текущей стабильной ветке приложения.
            </p>
            <div className="features-grid">
              {IMPLEMENTED_FEATURES.map((feat) => (
                <div key={feat.title} className="feature-card">
                  <span className="mono">{feat.tag}</span>
                  <h3>{feat.title}</h3>
                  <p>{feat.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="statement wrap">
          <p>
            Telegram остаётся Telegram: те же чаты, те же люди. <em>Меняется всё вокруг</em> — как приложение выглядит,
            как подключается и как ведёт себя на вашем телефоне.
          </p>
        </section>

        <section className="demo-section" id="demo">
          <div className="wrap section-pad">
            <Eyebrow>01 / ПРИЛОЖЕНИЕ ИЗНУТРИ</Eyebrow>
            <h2>
              Нажимайте <em>и листайте.</em>
            </h2>
            <div className="demo-grid">
              <div className="demo-left">
                <p className="section-lead">
                  Телефон справа — рабочий макет: тапайте по чатам, аккаунтам, узлам прокси и настройкам оформления.
                </p>
                <div className="demo-accordion">
                  {SCREENS.map((s, i) => (
                    <button
                      type="button"
                      key={s.id}
                      onClick={() => {
                        setScreen(s.id);
                        if (s.id === 'chats') setChatListRevision((value) => value + 1);
                      }}
                      className={screen === s.id ? 'active' : ''}
                      aria-expanded={screen === s.id}
                    >
                      <span>0{i + 1}</span>
                      <span>
                        <b>{s.title}</b>
                        {screen === s.id && <small>{s.text}</small>}
                      </span>
                    </button>
                  ))}
                </div>
                <div className="demo-controls">
                  <b>Настройте пример</b>
                  <label>
                    Радиус пузыря <span>{radius} dp</span>
                    <input type="range" min="4" max="24" value={radius} onChange={(e) => setRadius(+e.target.value)} />
                  </label>
                  <label>
                    Размер текста <span>{textSize} sp</span>
                    <input type="range" min="12" max="22" value={textSize} onChange={(e) => setTextSize(+e.target.value)} />
                  </label>
                </div>
              </div>
              <div className="demo-phone">
                <Phone
                  screen={screen}
                  account={account}
                  accent={accent}
                  radius={radius}
                  textSize={textSize}
                  onScreen={setScreen}
                  onAccount={setAccount}
                  chatListRevision={chatListRevision}
                />
                <p className="mono mock-note">Интерактивная иллюстрация, не скриншот приложения.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="wrap section-pad accounts-section" id="accounts">
          <div>
            <Eyebrow>02 / АККАУНТЫ</Eyebrow>
            <h2>
              Работа и личное — <em>рядом, но не вперемешку.</em>
            </h2>
            <p className="section-lead">
              Несколько аккаунтов Telegram в одном приложении. Переключайтесь одним касанием — у каждого аккаунта свои чаты.
            </p>
            <div className="account-switch">
              {ACCOUNTS.map((a, i) => (
                <button
                  type="button"
                  key={a.name}
                  onClick={() => setAccount(i as Account)}
                  className={account === i ? 'current' : ''}
                >
                  <span className="avatar" style={{ background: a.color }}>
                    {a.avatar}
                  </span>
                  <span>
                    <b>{a.name}</b>
                    <small>{a.detail}</small>
                  </span>
                  <span className="account-count">{a.count || '·'}</span>
                </button>
              ))}
            </div>
            <p className="mono mock-note">Имена и переписки — вымышленные.</p>
          </div>
          <div className="accounts-phone">
            <Phone screen="chats" account={account} accent={accent} radius={radius} textSize={textSize} interactive={false} />
          </div>
        </section>

        <section className="proxy-section" id="proxy">
          <div className="wrap section-pad">
            <Eyebrow>03 / ПРОКСИ</Eyebrow>
            <h2>
              Связь пропала?
              <br />
              <em>Приложение разберётся.</em>
            </h2>
            <p className="section-lead">
              Подключите подписку один раз. Если Telegram долго не может подключиться, BeyGram может проверить доступные узлы и
              переключиться на подходящий — без системного VPN-профиля.
            </p>
            <ProxyDemo />
          </div>
        </section>

        <section className="media-section" id="media">
          <div className="wrap section-pad">
            <Eyebrow>04 / МЕДИА</Eyebrow>
            <h2>
              Кружки, голосовые,
              <br />
              фото и видео.
            </h2>
            <p className="section-lead">
              Просмотр фото, видео и аудио, отправка файлов с подписью, плеер-трансформер и музыкальные списки.
            </p>
            <MediaDemo />
          </div>
        </section>

        <section className="beta-section" id="obt">
          <div className="wrap section-pad">
            <Eyebrow>05 / КАК УСТАНОВИТЬ И ВОЙТИ В ОБТ</Eyebrow>
            <h2>
              Четыре шага <em>до запуска.</em>
            </h2>
            <div className="install-steps">
              <div className="install-step">
                <span className="mono">01</span>
                <h3>Скачайте Stable APK</h3>
                <p>Используйте кнопку «Скачать BeyGram» выше или официальный раздел GitHub Releases.</p>
              </div>
              <div className="install-step">
                <span className="mono">02</span>
                <h3>Разрешите установку</h3>
                <p>При первом запуске файла Android попросит разрешить установку приложений из браузера или проводника.</p>
              </div>
              <div className="install-step">
                <span className="mono">03</span>
                <h3>Войдите и обновляйтесь безопасно</h3>
                <p>
                  Обновления проверяются вручную в «Настройки → Обновления» с проверкой SHA-256 и подписи. Не удаляйте приложение перед
                  обновлением.
                </p>
              </div>
              <div className="install-step">
                <span className="mono">04</span>
                <h3>Присоединяйтесь к ОБТ</h3>
                <p>
                  Следите за новыми сборками и оставляйте отзывы в Telegram-канале{' '}
                  <a href={CHANNEL} target="_blank" rel="noopener noreferrer">
                    @beygram_client ↗
                  </a>
                  .
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="wrap section-pad" id="faq">
          <Eyebrow>06 / FAQ И ПОДДЕРЖКА</Eyebrow>
          <h2>
            Частые <em>вопросы.</em>
          </h2>
          <div className="faq-list">
            {FAQ_ITEMS.map((item, idx) => {
              const isOpen = openFaq === idx;
              return (
                <div key={item.q} className="faq-item">
                  <button
                    type="button"
                    className="faq-q"
                    aria-expanded={isOpen}
                    onClick={() => setOpenFaq(isOpen ? null : idx)}
                  >
                    <span>{item.q}</span>
                    <span className="mono">{isOpen ? '−' : '+'}</span>
                  </button>
                  {isOpen && <p className="faq-a">{item.a}</p>}
                </div>
              );
            })}
          </div>
        </section>

        <section className="dev-section" id="dev">
          <div className="wrap section-pad dev-grid">
            <div>
              <Eyebrow>07 / ДЛЯ РАЗРАБОТЧИКОВ И БАГ-РЕПОРТЫ</Eyebrow>
              <h2>
                Код открыт.
                <br />
                <em>Читайте, собирайте, правьте.</em>
              </h2>
              <p>
                Android-клиент — Kotlin, Jetpack Compose и TDLib. Прокси на базе Mihomo, сервер диагностики на FastAPI. Лицензия GPL v3.
              </p>
              <div className="tech-tags">
                {['Kotlin', 'Jetpack Compose', 'TDLib', 'Mihomo', 'FastAPI', 'GPL v3'].map((t) => (
                  <span key={t}>{t}</span>
                ))}
              </div>
              <div className="dev-links">
                <a href={GITHUB} target="_blank" rel="noopener noreferrer">
                  BeyGram — Android-клиент ↗
                </a>
                <a href={DIAGNOSTICS_GITHUB} target="_blank" rel="noopener noreferrer">
                  BeyGram — сервер диагностики и сайт ↗
                </a>
                <a href={GITHUB + '/issues'} target="_blank" rel="noopener noreferrer">
                  Сообщить об ошибке (GitHub Issues) ↗
                </a>
                <a href={CHANNEL} target="_blank" rel="noopener noreferrer">
                  Telegram-канал ОБТ (@beygram_client) ↗
                </a>
              </div>
            </div>
            <div>
              <Eyebrow>СОСТОЯНИЕ ЭКОСИСТЕМЫ</Eyebrow>
              {[
                ['ОБТ · STABLE', 'Android-клиент: чаты, форумы 2.0, плеер, Mihomo, мультиаккаунтинг'],
                ['РАБОТАЕТ', 'Уведомления без Google-сервисов, BG Push, диагностика по кнопке'],
                ['В РАЗРАБОТКЕ', 'BeyGram iOS (ветка 0.0.1 DEV на базе Telegram-iOS)'],
                ['В РАЗРАБОТКЕ', 'BeyGram Windows (ранний этап разработки)'],
              ].map(([status, description], i) => (
                <div className="dev-status" key={i}>
                  <span className={i < 2 ? 'ready' : 'planned'}>{status}</span>
                  <span>{description}</span>
                </div>
              ))}
              <p className="status-disclaimer">
                Релизы iOS и Windows появятся на сайте только после публикации официальных установочных сборок.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div className="wrap footer-grid">
          <div>
            <b>BeyGram</b>
            <p>Независимый Telegram-клиент с открытым исходным кодом. Не аффилирован с Telegram.</p>
          </div>
          <div>
            <Eyebrow>СООБЩЕСТВО</Eyebrow>
            <a href={CHANNEL} target="_blank" rel="noopener noreferrer">
              Telegram-канал ↗
            </a>
            <a href={GITHUB + '/issues'} target="_blank" rel="noopener noreferrer">
              Сообщить о проблеме ↗
            </a>
          </div>
          <div>
            <Eyebrow>ПРОЕКТ</Eyebrow>
            <a href={GITHUB} target="_blank" rel="noopener noreferrer">
              Исходный код ↗
            </a>
            <a href={ANDROID_RELEASES_URL} target="_blank" rel="noopener noreferrer">
              Релизы на GitHub ↗
            </a>
            <a href={GITHUB + '/blob/DEV/LICENSE'} target="_blank" rel="noopener noreferrer">
              Лицензия GPL v3 ↗
            </a>
          </div>
        </div>
        <div className="wrap footer-end">
          © {new Date().getFullYear()} BeyGram · Android 10+ · Открытое бета-тестирование
        </div>
      </footer>
    </>
  );
}
