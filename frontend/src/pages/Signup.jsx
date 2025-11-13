import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import '../index.css';

const Signup = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'user'
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { signup } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await signup(formData.name, formData.email, formData.password, formData.role);
      navigate('/dashboard');
    } catch (error) {
      setError(error.response?.data?.error || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="auth-container">
      <div className="auth-form">
        <h2 className="auth-title">Create your account</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <input
              name="name"
              type="text"
              required
              className="form-input"
              placeholder="Full name"
              value={formData.name}
              onChange={handleChange}
            />
          </div>
          <div className="form-group">
            <input
              name="email"
              type="email"
              required
              className="form-input"
              placeholder="Email address"
              value={formData.email}
              onChange={handleChange}
            />
          </div>
          <div className="form-group">
            <input
              name="password"
              type="password"
              required
              className="form-input"
              placeholder="Password"
              value={formData.password}
              onChange={handleChange}
            />
          </div>
          <div className="form-group">
            <select
              name="role"
              className="form-input"
              value={formData.role}
              onChange={handleChange}
            >
              <option value="user">Job Seeker</option>
              <option value="admin">Recruiter</option>
            </select>
          </div>

          {error && (
            <div className="error-message">{error}</div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="form-button"
          >
            {loading ? 'Creating account...' : 'Sign up'}
          </button>

          <div className="auth-link">
            <span>Already have an account? <Link to="/login">Sign in</Link></span>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Signup;