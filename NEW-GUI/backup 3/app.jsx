/* global React, ReactDOM, DashboardMode, TraceMode, ChatMode, PlanMode, NotesMode, InterestsMode, CaidoMode, Rail */
const { useState: useStateApp } = React;

const TWEAKS = /*EDITMODE-BEGIN*/{
  "accent": "cyan",
  "density": "compact",
  "contrast": "extra",
  "monoFont": "JetBrains Mono",
  "showGlobe": true,
  "cyberpunk": true
}/*EDITMODE-END*/;

function App() {
  const [mode, setMode] = useStateApp('trace');
  const [tweaks, setTweak] = window.useTweaks ? window.useTweaks(TWEAKS) : [TWEAKS, () => {}];

  // apply accent live
  React.useEffect(() => {
    const root = document.documentElement;
    const map = {
      cyan: '#2aa198', blue: '#268bd2', violet: '#6c71c4', green: '#859900', yellow: '#b58900',
    };
    const c = map[tweaks.accent] || map.cyan;
    root.style.setProperty('--cyan', c);
    root.style.setProperty('--cyan-soft', c + '2a');
  }, [tweaks.accent]);

  React.useEffect(() => {
    document.body.classList.toggle('cyberpunk', !!tweaks.cyberpunk);
  }, [tweaks.cyberpunk]);

  React.useEffect(() => {
    const root = document.documentElement;
    if (tweaks.contrast === 'extra') {
      root.style.setProperty('--bg-deep', '#000d12');
      root.style.setProperty('--bg', '#001620');
      root.style.setProperty('--txt', '#a8b8b6');
      root.style.setProperty('--txt-strong', '#dde7e6');
      root.style.setProperty('--txt-hi', '#fdf6e3');
    } else if (tweaks.contrast === 'standard') {
      root.style.setProperty('--bg-deep', '#002b36');
      root.style.setProperty('--bg', '#073642');
      root.style.setProperty('--txt', '#839496');
      root.style.setProperty('--txt-strong', '#93a1a1');
      root.style.setProperty('--txt-hi', '#eee8d5');
    } else {
      root.style.setProperty('--bg-deep', '#001a22');
      root.style.setProperty('--bg', '#002b36');
      root.style.setProperty('--txt', '#93a1a1');
      root.style.setProperty('--txt-strong', '#c8d4d3');
      root.style.setProperty('--txt-hi', '#fdf6e3');
    }
  }, [tweaks.contrast]);

  return (
    <>
      <Rail mode={mode} setMode={setMode} />
      <div className="mode" data-screen-label={mode}>
        {mode === 'dashboard' && <DashboardMode tweaks={tweaks} />}
        {mode === 'trace'     && <TraceMode     tweaks={tweaks} />}
        {mode === 'chat'      && <ChatMode      tweaks={tweaks} />}
        {mode === 'pair'      && <PlanMode      tweaks={tweaks} />}
        {mode === 'notion'    && <NotesMode     tweaks={tweaks} />}
        {mode === 'interests' && <InterestsMode tweaks={tweaks} />}
        {mode === 'caido'     && <CaidoMode     tweaks={tweaks} />}
      </div>

      {window.TweaksPanel && (
        <window.TweaksPanel title="Tweaks">
          <window.TweakSection label="Theme">
            <window.TweakRadio
              label="Contrast"
              value={tweaks.contrast}
              options={['standard', 'high', 'extra']}
              onChange={v => setTweak('contrast', v)}
            />
            <window.TweakRadio
              label="Accent"
              value={tweaks.accent}
              options={['cyan', 'blue', 'violet', 'green', 'yellow']}
              onChange={v => setTweak('accent', v)}
            />
            <window.TweakToggle
              label="Cyberpunk flare"
              value={tweaks.cyberpunk}
              onChange={v => setTweak('cyberpunk', v)}
            />
          </window.TweakSection>
          <window.TweakSection label="Layout">
            <window.TweakRadio
              label="Mode"
              value={mode}
              options={['dashboard', 'trace', 'chat', 'pair', 'notion', 'interests', 'caido']}
              onChange={v => setMode(v)}
            />
            <window.TweakToggle
              label="Show globe"
              value={tweaks.showGlobe}
              onChange={v => setTweak('showGlobe', v)}
            />
          </window.TweakSection>
        </window.TweaksPanel>
      )}
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
