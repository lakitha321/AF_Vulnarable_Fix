import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";
import { UserContext } from "../App";

function StaffRegister() {

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

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

        const newStaff = {
            name,
            email,
            age,
            gender,
            nic,
            address,
            mobile,
            password
        }

        axios.post("http://localhost:8070/staff/add", newStaff).then((res)=>{
            alert(res.data);
            navigate("/allstaff");
        }).catch((err)=>{
            alert(err);
        })
    }
  
    return (
        <div className="container mt-5">
            <br/><br/>
            <Card style={{ width: '68rem', margin:"auto" }}>
            <Card.Body>
                <Card.Title>Register a new Staff member</Card.Title>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Label>Full name</Form.Label>
                        <Form.Control type="text" placeholder="Full name" pattern="[a-zA-Z][a-zA-Z. ]{3,}"
                        onChange={(e) => {
                            setName(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Name.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="6" controlId="validationCustom04">
                        <Form.Label>Email</Form.Label>
                        <Form.Control type="email" placeholder="Email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                        onChange={(e) => {
                            setEmail(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Email.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="2" controlId="validationCustom04">
                        <Form.Label>Age</Form.Label>
                        <Form.Control type="text" placeholder="Age" pattern="[0-9][0-9]"
                        onChange={(e) => {
                            setAge(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Age (XX).
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="2" controlId="validationCustom04">
                        <Form.Label>Gender</Form.Label>
                        <select id="inputState" class="form-select"
                        onChange={(e) => {
                            setGender(e.target.value);
                        }}
                        required>
                        <option selected></option>
                        <option>Male</option>
                        <option>Female</option>
                        </select>
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Gender.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="4" controlId="validationCustom04">
                        <Form.Label>NIC</Form.Label>
                        <Form.Control type="text" placeholder="NIC" pattern="[0-9]{9,12}"
                        onChange={(e) => {
                            setNic(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid NIC.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Row} md="11" controlId="validationCustom03">
                        <Form.Label>Address</Form.Label>
                        <Form.Control type="text" placeholder="Address" pattern="[a-zA-Z0-9._+-/(), ]{10,}"
                        onChange={(e) => {
                            setAddress(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Address.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="3" controlId="validationCustom04">
                        <Form.Label>Mobile number</Form.Label>
                        <Form.Control type="tel" placeholder="Mobile number" pattern="[0][0-9]{9}"
                        onChange={(e) => {
                            setMobile(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Mobile number (0XXXXXXXXX).
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="3" controlId="validationCustom05">
                        <Form.Label>Password</Form.Label>
                        <Form.Control type="password" placeholder="Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}"
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
                    <Button className="btn btn-success" type="submit" style={{opacity: "70%"}}>Save</Button>
                </Form>
            </Card.Body>
            </Card>
            <br/><br/><br/>
        </div>
    );
}
  
export default StaffRegister;