import { Layout } from './components/Layout';
import './App.css';

function App() {
  return (
    <Layout>
      <div className="app-home">
        <h1>Welcome to Kuro</h1>
        <p>eBPF-based Distributed Network Simulator</p>
        <div className="app-home__cards">
          <div className="app-home__card">
            <h3>🌐 Network Topologies</h3>
            <p>Visualize and manage your network simulation topologies</p>
          </div>
          <div className="app-home__card">
            <h3>📊 Real-time Metrics</h3>
            <p>Monitor bandwidth, latency, and packet loss in real-time</p>
          </div>
          <div className="app-home__card">
            <h3>⚙️ Traffic Control</h3>
            <p>Configure link parameters with precision using eBPF</p>
          </div>
        </div>
      </div>
    </Layout>
  );
}

export default App;
