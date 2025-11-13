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
          <h1 className="navbar-brand">CareerLink</h1>
          <div className="navbar-user">
            <span>Welcome, {user?.name}</span>
            <span className="user-badge">
              {user?.role === 'admin' ? 'Recruiter' : 'Job Seeker'}
            </span>
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          </div>
        </div>
      </nav>

      <main className="main-content">
        <div className="dashboard-placeholder">
          <div className="dashboard-welcome">
            <h2>Welcome to CareerLink Dashboard</h2>
            <p>
              {user?.role === 'admin' 
                ? 'You can post and manage job listings here.' 
                : 'You can browse and apply for jobs here.'
              }
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;