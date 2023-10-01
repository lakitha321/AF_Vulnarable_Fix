import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate, useParams } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";
import { UserContext } from "../App";


const User = () => {
    const { id, name, email, age, gender, nic, address, mobile, password } = useParams();

    const details = {
        id,
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password
    }

    return details;
}

function StaffUpdate() {
    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const data = User();

    const [validated, setValidated] = useState(false);
    const navigate = useNavigate();

    const [name, setName] = useState(data.name);
    const [email, setEmail] = useState(data.email);
    const [age, setAge] = useState(data.age);
    const [gender, setGender] = useState(data.gender);
    const [nic, setNic] = useState(data.nic);
    const [address, setAddress] = useState(data.address);
    const [mobile, setMobile] = useState(data.mobile);
    const [password, setPassword] = useState(data.password);
  
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

        const updateSudent = {
            name,
            email,
            age,
            gender,
            nic,
            address,
            mobile,
            password
        }

        axios.put(`http://localhost:8070/staff/update/${data.id}`, updateSudent).then((res)=>{
            alert(res.data.msg);
            if(res.data.status){
                navigate("/allstaff");
            }
            
        }).catch((err)=>{
            alert(err);
        })
    }
  
    return (
        <div className="container mt-5">
            <br/><br/>
            <Card style={{ width: '68rem', margin:"auto" }}>
            <Card.Body>
                <Card.Title>Update Staff member</Card.Title>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Label>Full name</Form.Label>
                        <Form.Control type="text" placeholder="Full name" defaultValue={data.name} pattern="[a-zA-Z][a-zA-Z. ]{3,}"
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
                        <Form.Control type="email" placeholder="Email" defaultValue={data.email} pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
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
                        <Form.Control type="text" placeholder="Age" defaultValue={data.age} pattern="[0-9][0-9]"
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
                        <option selected>{data.gender}</option>
                        <option>Male</option>
                        <option>Female</option>
                        </select>
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Gender.
                        </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group as={Col} md="4" controlId="validationCustom04">
                        <Form.Label>NIC</Form.Label>
                        <Form.Control type="text" placeholder="NIC" defaultValue={data.nic} pattern="[0-9]{9,12}"
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
                        <Form.Control type="text" placeholder="Address" defaultValue={data.address} pattern="[a-zA-Z0-9._+-/(), ]{10,}"
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
                        <Form.Control type="tel" placeholder="Mobile number" defaultValue={data.mobile} pattern="[0][0-9]{9}"
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
                        <Form.Control type="password" placeholder="Password" defaultValue={data.password} pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}"
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
                    <Button className="btn btn-primary" type="submit" style={{opacity: "70%"}}>Save changes</Button>
                </Form>
            </Card.Body>
            </Card>
            <br/><br/><br/>
        </div>
    );
}
  
export default StaffUpdate;