import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import '../index.css';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="dashboard">
      <nav className="navbar">
        <div className="navbar-content">
          <h1 className="navbar-brand">FlexVault</h1>
          <div className="navbar-user">
            <span>Welcome, {user?.name}</span>
            
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          </div>
        </div>
      </nav>

      <main className="main-content">
        <div className="dashboard-placeholder">
          <div className="dashboard-welcome">
            <h2>Welcome to FlexVault Dashboard</h2>
            
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;