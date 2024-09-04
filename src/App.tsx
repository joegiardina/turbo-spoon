import React, {useState} from 'react';
import logo from './logo.svg';
import './App.css';
import { signIn, signUp, confirmSignUp, signOut } from './aws/authService';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [confirmationCode, setConfirmationCode] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const accessToken = sessionStorage.getItem('accessToken') || '';

  const handleSignIn = async (e: {preventDefault: () => void}) => {
    e.preventDefault();
    try {
      const session = await signIn(email, password);
      console.log('Sign in successful', session);
      if (session && typeof session.AccessToken !== 'undefined') {
        sessionStorage.setItem('accessToken', session.AccessToken);
        if (sessionStorage.getItem('accessToken')) {
          window.location.href = '/home';
        } else {
          console.error('Session token was not set properly.');
        }
      } else {
        console.error('SignIn session or AccessToken is undefined.');
      }
    } catch (error) {
      alert(`Sign in failed: ${error}`);
    }
  };

  const handleSignUp = async (e: {preventDefault: () => void}) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    try {
      await signUp(email, password);
    } catch (error) {
      alert(`Sign up failed: ${error}`);
    }
  };

  const handleConfirm = async (e: {preventDefault: () => void}) => {
    e.preventDefault();
    try {
      await confirmSignUp(email, confirmationCode);
      alert("Account confirmed successfully!\nSign in on next page.");
    } catch (error) {
      alert(`Failed to confirm account: ${error}`);
    }
  };
  
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Welcome
        </p>
          {!accessToken ? (
            <>
              <form onSubmit={isSignUp ? handleSignUp : handleSignIn}>
                <div style={{flex: 1, flexDirection: 'column'}}>
                  <div>
                    <TextField
                      id="email"
                      type="email"
                      label="Email"
                      margin="dense"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div>
                    <TextField
                      id="password"
                      type="password"
                      label="Password"
                      margin="dense"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                  {isSignUp && (
                    <>
                      <div>
                        <TextField
                          className="inputText"
                          id="confirmPassword"
                          type="password"
                          label="Confirm Password"
                          margin="dense"
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                          required
                        />
                      </div>
                      <div>
                        <TextField
                          className="inputText"
                          id="confirmationCode"
                          type="numeric"
                          label="Confirmation Code"
                          margin="dense"
                          value={confirmationCode}
                          onChange={(e) => setConfirmationCode(e.target.value)}
                        />
                      </div>
                    </>
                  )}
                  <Button type="submit">{isSignUp ? 'Sign Up' : 'Sign In'}</Button>
                </div>
              </form>
              <Button onClick={() => setIsSignUp(!isSignUp)}>
                {isSignUp ? 'Already have an account? Sign In' : 'Need an account? Sign Up'}
              </Button>
              {isSignUp && (
                <Button onClick={handleConfirm}>
                  Confirm
                </Button>
              )}
            </>
          ) : null}
          <Button onClick={async () => {  
            const accessToken = sessionStorage.getItem('accessToken') || '';
            try {
              const resp = await fetch('https://w1e1ps4u4l.execute-api.us-west-1.amazonaws.com/test/cog-test', {
                headers: {
                  Authorization: accessToken
                }
              });
              alert(resp.status);
            } catch (e: any) {
              alert('failed')
            }
          }}>
            Test auth
          </Button>
          {accessToken && (
            <Button onClick={(e) => {
              signOut();
              window.location.reload();
            }}>
              Sign Out
            </Button>
          )}
      </header>
    </div>
  );
}

export default App;
