import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/Signup.css"

const Signup: React.FC = () => {
  let navigate = useNavigate();
  const [firstName, setFirstName] = useState<string | null>(null);
  const [lastName, setLastName] = useState<string | null>(null);
  const [loginId, setLoginId] = useState<string | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [confirmPassword, setConfirmPassword] = useState<string | null>(null);
  const [isFormValid, setIsFormValid] = useState<boolean>(false);

  useEffect(() => {
    if (firstName && lastName && loginId && password && confirmPassword && password === confirmPassword) {
      setIsFormValid(true);
    } else {
      setIsFormValid(false);
    }
  }, [firstName, lastName, loginId, password, confirmPassword]);

  const handleSignupSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isFormValid) {
      alert("모든 필드를 올바르게 입력해 주세요.");
      return;
    }

    try {
      const signUpResponse = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/auth/signup`, {
        method: "POST",
        credentials: 'include',
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          firstName,
          lastName,
          loginId,
          password,
        }),
      });

      if(signUpResponse.ok) {
        alert("회원가입이 완료되었습니다.");
        navigate("/login");
      }else{
        const errorMessage = await signUpResponse.text();
        throw new Error(errorMessage);
      }
    } catch (error) {
      if(error instanceof Error){
        window.alert(error.message);
      }
    }
  };

  return (
    <div className="signup-wrapper">
      <p className="signupTitle">Sign up to VirusDecode</p>
      <form className="signupForm" onSubmit={handleSignupSubmit}>
        <div className="name-container">
          <div className="name-field">
            <input 
              className="signupInput"
              type="text" 
              name="firstName" 
              placeholder=" "
              onChange={(e) => setFirstName(e.target.value)}
            />
            <label className="signupLabel" htmlFor="firstName">First Name</label>
          </div>
          <div className="name-field">
            <input 
              className="signupInput"
              type="text" 
              name="lastName" 
              placeholder=" "
              onChange={(e) => setLastName(e.target.value)}
            />
            <label className="signupLabel" htmlFor="lastName">Last Name</label>
          </div>
        </div>
        <div className="input-container">
          <input 
            className="signupInput"
            type="text" 
            name="id" 
            placeholder=" "
            onChange={(e) => setLoginId(e.target.value)}
          />
          <label className="signupLabel" htmlFor="id">ID</label>
        </div>
        <div className="input-container">
          <input 
            className="signupInput"
            type="password" 
            name="password" 
            placeholder=" "
            onChange={(e) => setPassword(e.target.value)}
          />
          <label className="signupLabel" htmlFor="password">Password</label>
        </div>
        <div className="input-container">
          <input 
            className="signupInput"
            type="password" 
            name="cPassword" 
            placeholder=" "
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          <label className="signupLabel" htmlFor="cPassword">Confirm Password</label>
        </div>
        <button className="SignupBtn" type="submit">
          Signup
        </button>
      </form>
      <button className="gotoLoginBtn" onClick={() => navigate("/login")}>
        Back to Login
      </button>
    </div>
  )
}
export default Signup;