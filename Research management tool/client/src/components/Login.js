import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, InputGroup, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

function Login() {

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);

    const [validated, setValidated] = useState(false);

    const [email, setEmail] = useState();
    const [password, setPass] = useState();
    const [role, setRole] = useState();
  
    const handleSubmit = (event) => {
      const form = event.currentTarget;
      if(form.checkValidity()==true){
        event.preventDefault();
        event.stopPropagation();
        if(role === "Student"){
            studentNav();
        }
        if(role === "Staff"){
            staffNav();
        }
        if(role === "Admin"){
            adminNav();
        }
        
      }
      else{
        if (form.checkValidity() == false) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        setValidated(true); 
      }
      
    };

    const studentNav = () => {

        const validateStaff = {
            password
        }

        axios.post(`http://localhost:8070/student/log/${email}`, validateStaff).then((res)=>{
            if(res.data.status){

                localStorage.setItem("sid", res.data.Students._id);
                localStorage.setItem("sname", res.data.Students.name);
                localStorage.setItem("semail", res.data.Students.email);
                localStorage.setItem("sage", res.data.Students.age);
                localStorage.setItem("sgender", res.data.Students.gender);
                localStorage.setItem("snic", res.data.Students.nic);
                localStorage.setItem("saddress", res.data.Students.address);
                localStorage.setItem("smobile", res.data.Students.mobile);
                localStorage.setItem("spassword", res.data.Students.password);
                localStorage.setItem("sgroupid", res.data.Students.groupid);

                alert('loged successfuly');

                dispatch({type:"USER", payload:1})
                window.location.assign('/home');
            }
            else{
                alert('Invalid username or password')
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    const staffNav = () => {

        const validateStudent = {
            password
        }

        axios.post(`http://localhost:8070/staff/log/${email}`, validateStudent).then((res)=>{
            if(res.data.status){

                localStorage.setItem("stfid", res.data.Staffs._id);
                localStorage.setItem("stfname", res.data.Staffs.name);
                localStorage.setItem("stfemail", res.data.Staffs.email);
                localStorage.setItem("stfage", res.data.Staffs.age);
                localStorage.setItem("stfgender", res.data.Staffs.gender);
                localStorage.setItem("stfnic", res.data.Staffs.nic);
                localStorage.setItem("stfaddress", res.data.Staffs.address);
                localStorage.setItem("stfmobile", res.data.Staffs.mobile);
                localStorage.setItem("stfpassword", res.data.Staffs.password);
                localStorage.setItem("stfrole", res.data.Staffs.role);
                localStorage.setItem("stfresearch", res.data.Staffs.research);

                alert('loged successfuly');

                dispatch({type:"USER", payload:3})
                window.location.assign('/stfhome');
            }
            else{
                alert('Invalid username or password')
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    const adminNav = () => {
        const firstpassword = password;
        const validateAdmin1 = {
            firstpassword
        }

        axios.post(`http://localhost:8070/admin/firstlog/${email}`, validateAdmin1).then((res)=>{
            if(res.data.status){
                localStorage.setItem("aemail", email);
                alert('Step 1 authenticated');
                navigate("/adminlog");
            }
            else{
                alert('Invalid username or password')
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    return (
        <div className="container">
            <br/><br/><br/>
            <Card style={{backgroundColor : 'transparent', width: '38rem', margin:"auto" }}>
            <Card.Body align="center">
                <Card.Title style={{color : 'white'}}>Sign in</Card.Title><br/>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="6" controlId="validationCustom04">
                        <Form.Label align="left" style={{color : 'white'}}>Email</Form.Label>
                        <Form.Control type="email" placeholder="Email" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setEmail(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please enter your Email
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="3" controlId="validationCustom05">
                        <Form.Label align="left" style={{color : 'white'}} className='mt-3'>Password</Form.Label>
                        <Form.Control type="password" placeholder="Password" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setPass(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please enter your Password
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="2" controlId="validationCustom04">
                        <Form.Label align="left" style={{color : 'white'}} className='mt-3'>Role</Form.Label>
                        <select id="inputState" class="form-select" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setRole(e.target.value);
                        }}
                        required>
                        <option selected style={{backgroundColor : 'black'}}></option>
                        <option style={{backgroundColor : 'black', color : 'white'}}>Student</option>
                        <option style={{backgroundColor : 'black', color : 'white'}}>Staff</option>
                        <option style={{backgroundColor : 'black', color : 'white'}}>Admin</option>
                        </select>
                        <Form.Control.Feedback type="invalid">
                        Please select your Role
                        </Form.Control.Feedback>
                    </Form.Group>
                    </Row>
                    <br/>
                    <Button type="submit" style={{width: '18rem'}}>Sign in</Button>
                </Form>
            </Card.Body>
            </Card>
        </div>
    );
}
  
export default Login;