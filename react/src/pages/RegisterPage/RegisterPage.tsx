import React,{ useState } from 'react';
import './register.css'
import { useNavigate } from 'react-router-dom';
import { registerService } from '../../services/userService';
import { useDispatch, useSelector } from 'react-redux';
import { updateUser } from '../../redux/slides/userSlide';
import { RootState } from '../../redux/store';
import { userRegister } from '../../model/UserModal';

export default function RegisterPage() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState<userRegister>({
    username: '',
    email: '',
    password: '',
    password2: '',
  });
  const user = useSelector((state:RootState)=> state.user); console.log(user);
  const dispatch = useDispatch();

  const [error, setError] = useState({
    isInvalid : false,
    msg : ''
  })

  console.log(formData)

  const handleSignUp = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if(formData.password !== formData.password2 && formData.password2 !== ''){
      setError({
        isInvalid : true,
        msg : 'Confirm password is not matching'       
      })
    }else{
      const res = await registerService(formData);
      console.log(res)
      if(res?.success){
        navigate('/')
        dispatch(updateUser({...user , username : res?.data}))
      }else{
        setError({
          isInvalid : true,
          msg : res?.message        
        })
      }
    }
  }


  return (
    <div id='RegisterPage' className='background' style={{height:"100vh"}}>
      <div className='container'>
        <h1>Register</h1>
        <form onSubmit={handleSignUp}>
          <div className='form-control'>
            <input 
              required 
              type="text" 
              name="username" 
              value={formData.username}
              id="username" 
              placeholder="Username" 
              onChange={e => setFormData({...formData,[e.target.name] : e.target.value})}
            />
            <span></span>
            <small>{(error?.isInvalid && error?.msg.includes('Username')) ? error?.msg : ''}</small>
          </div>
          <div className='form-control'>
            <input 
              required 
              name="email"
              value={formData.email}
              id="email" 
              placeholder="Email" 
              onChange={e => setFormData({...formData,[e.target.name] : e.target.value})}
            />
            <span></span>
            <small>{(error?.isInvalid && error?.msg.includes('Email')) ? error?.msg : ''}</small>
          </div>
          <div className='form-control'>
            <input 
              required 
              type="password"
              name="password" 
              value={formData.password}
              id="password"
              placeholder="Password"               
              onChange={e => setFormData({...formData,[e.target.name] : e.target.value})}
            />
            <span></span>
            <small>{(error?.isInvalid && error?.msg.includes('Password')) ? error?.msg : ''}</small>
          </div>
          <div className='form-control'>
            <input
              required
              type="password"
              name="password2"
              value={formData.password2}
              id="password2"
              placeholder="Confirm password"
              onChange={e => setFormData({...formData,[e.target.name] : e.target.value})}
            />
            <span></span>
            <small>{(error?.isInvalid && error?.msg.includes('Confirm password')) ? error?.msg : ''}</small>
          </div>
          <input type='submit' value="Register" />
          <div className="signup_link">Already a member? <a href="#" onClick={() => navigate('/sign-in')}>Login</a></div>				
        </form>
      </div>
    </div>
  )
}
