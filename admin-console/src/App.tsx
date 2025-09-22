import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Dashboard } from './components/Dashboard';
import { PolicyEditor } from './components/PolicyEditor';
import { ReceiptBrowser } from './components/ReceiptBrowser';
import { AuditExport } from './components/AuditExport';
import './App.css';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="app">
        <header className="app-header">
          <h1>Benteng Admin Console</h1>
        </header>
        <nav className="app-nav">
          <a href="#dashboard">Dashboard</a>
          <a href="#policies">Policies</a>
          <a href="#receipts">Receipts</a>
          <a href="#audit">Audit</a>
        </nav>
        <main className="app-content">
          <Dashboard />
          <PolicyEditor />
          <ReceiptBrowser />
          <AuditExport />
        </main>
      </div>
    </QueryClientProvider>
  );
}

export default App;
