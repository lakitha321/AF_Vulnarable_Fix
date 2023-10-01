import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";
import { UserContext } from "../App";


function StudentRegister() {
    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:0})

    const [validated, setValidated] = useState(false);
    const navigate = useNavigate();

    const [name, setName] = useState("");
    const [email, setEmail] = useState("");
    const [age, setAge] = useState("");
    const [gender, setGender] = useState("");
    const [nic, setNic] = useState("");
    const [address, setAddress] = useState("");
    const [mobile, setMobile] = useState("");
    const [password, setPassword] = useState("");
  
    const handleSubmit = (event) => {
        
      const form = event.currentTarget;
      if(form.checkValidity()==true){
        event.preventDefault();
        event.stopPropagation();
        sendData();
      }
      else{
        if (form.checkValidity() == false) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        setValidated(true); 
      }
    
    };
    const sendData = (e) => {

        const newStudent = {
            name,
            email,
            age,
            gender,
            nic,
            address,
            mobile,
            password
        }

        axios.post("http://localhost:8070/student/add", newStudent).then((res)=>{
            alert(res.data);
            navigate("/log");
        }).catch((err)=>{
            alert(err);
        })
    }
  
    return (
        <div className="container">
            <br/><br/>
            <Card style={{ width: '68rem', margin:"auto", backgroundColor : 'transparent' }}>
            <Card.Body>
                <Card.Title style={{color : 'white'}}>Student registration</Card.Title>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Full name</Form.Label>
                        <Form.Control type="text" placeholder="Full name" pattern="[a-zA-Z][a-zA-Z. ]{3,}" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setName(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Name.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="6" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Email</Form.Label>
                        <Form.Control type="email" placeholder="Email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setEmail(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Email.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="2" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Age</Form.Label>
                        <Form.Control type="text" placeholder="Age" pattern="[0-9][0-9]" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setAge(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Age (XX).
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="2" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Gender</Form.Label>
                        <select id="inputState" class="form-select" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setGender(e.target.value);
                        }}
                        required>
                        <option selected style={{backgroundColor : 'black'}}></option>
                        <option style={{backgroundColor : 'black'}}>Male</option>
                        <option style={{backgroundColor : 'black'}}>Female</option>
                        </select>
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Gender.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="4" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>NIC</Form.Label>
                        <Form.Control type="text" placeholder="NIC" pattern="[0-9]{9,12}" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setNic(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid NIC.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="11" controlId="validationCustom03">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Address</Form.Label>
                        <Form.Control type="text" placeholder="Address" pattern="[a-zA-Z0-9._+-/(), ]{10,}" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setAddress(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Address.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="3" controlId="validationCustom04">
                        <Form.Label style={{color : 'white'}} className='mt-3'>Mobile number</Form.Label>
                        <Form.Control type="tel" placeholder="Mobile number" pattern="[0][0-9]{9}" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setMobile(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Mobile number (0XXXXXXXXX).
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="3" controlId="validationCustom05" className='mb-5'>
                        <Form.Label style={{color : 'white'}} className='mt-3'>Password</Form.Label>
                        <Form.Control type="password" placeholder="Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setPassword(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Password.
                        Must contain at least one number and one uppercase and lowercase letter, and at least 6 or more characters
                        </Form.Control.Feedback>
                    </Form.Group>
                    </Row>
                    <Button type="submit" style={{width: '18rem'}}>Sign in</Button>
                </Form>
            </Card.Body>
            </Card>
        </div>
    );
}
  
export default StudentRegister;