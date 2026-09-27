import { useEffect, useState } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { Layout, BackgroundScene } from './components/Layout';
import { ShieldLoader } from './components/ShieldLoader';
import { Lookup } from './pages/Lookup';
import { History } from './pages/History';
import { pingBackend } from './lib/api';

// Long enough for one full pass of the shield streak, so the opening screen never
// just flashes when the backend answers instantly.
const MIN_SPLASH_MS = 2200;

function App() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const minDelay = new Promise((resolve) => setTimeout(resolve, MIN_SPLASH_MS));
    Promise.all([pingBackend(), minDelay]).then(() => setReady(true));
  }, []);

  return (
    <AnimatePresence mode="wait">
      {!ready ? (
        <motion.div
          key="splash"
          exit={{ opacity: 0 }}
          transition={{ duration: 0.35 }}
          style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}
        >
          <BackgroundScene />
          <ShieldLoader label="Connecting to live sources..." />
        </motion.div>
      ) : (
        <motion.div key="app" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.35 }}>
          <HashRouter>
            <Routes>
              <Route path="/" element={<Layout><Lookup /></Layout>} />
              <Route path="/history" element={<Layout><History /></Layout>} />
            </Routes>
          </HashRouter>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default App;
