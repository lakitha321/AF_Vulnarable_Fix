import React,{useState} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";

function AdminUpdate() {
    const [validated, setValidated] = useState(false);
    const navigate = useNavigate();

    const id = localStorage.getItem("aid");
    const [name, setName] = useState(localStorage.getItem("aname"));
    const [email, setEmail] = useState(localStorage.getItem("aemail"));
    const [nic, setNic] = useState(localStorage.getItem("anic"));
    const [mobile, setMobile] = useState(localStorage.getItem("amobile"));
    const [firstpassword, setFirstpassword] = useState(localStorage.getItem("afirstpassword"));
    const [secondpassword, setSecondpassword] = useState(localStorage.getItem("asecondpassword"));
  
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

        const updateAdmin = {
            name,
            email,
            nic,
            mobile,
            firstpassword,
            secondpassword
        }

        axios.put(`http://localhost:8070/admin/update/${id}`, updateAdmin).then((res)=>{
            alert(res.data.msg);
            if(res.data.status){
                localStorage.setItem("aid", id);
                localStorage.setItem("aname", updateAdmin.name);
                localStorage.setItem("aemail", updateAdmin.email);
                localStorage.setItem("anic", updateAdmin.nic);
                localStorage.setItem("amobile", updateAdmin.mobile);
                localStorage.setItem("afirstpassword", updateAdmin.firstpassword);
                localStorage.setItem("asecondpassword", updateAdmin.secondpassword);
                navigate("/adminhome");
            }
            
        }).catch((err)=>{
            alert(err);
        })
    }
  
    return (
        <div className="container mt-5">
            <Form noValidate validated={validated} onSubmit={handleSubmit}>
                <Row className="mb-3">
                <Form.Group as={Col} md="5" controlId="validationCustom04">
                    <Form.Label>Full name</Form.Label>
                    <Form.Control type="text" placeholder="Full name" defaultValue={name} pattern="[a-zA-Z][a-zA-Z. ]{3,}"
                    onChange={(e) => {
                        setName(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Name.
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Col} md="6" controlId="validationCustom04">
                    <Form.Label>Email</Form.Label>
                    <Form.Control type="email" placeholder="Email" defaultValue={email} pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                    onChange={(e) => {
                        setEmail(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Email.
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Col} md="4" controlId="validationCustom04">
                    <Form.Label>NIC</Form.Label>
                    <Form.Control type="text" placeholder="NIC" defaultValue={nic} pattern="[0-9]{9,12}"
                    onChange={(e) => {
                        setNic(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid NIC.
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Col} md="3" controlId="validationCustom04">
                    <Form.Label>Mobile number</Form.Label>
                    <Form.Control type="tel" placeholder="Mobile number" defaultValue={mobile} pattern="[0][0-9]{9}"
                    onChange={(e) => {
                        setMobile(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Mobile number (0XXXXXXXXX).
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Col} md="3" controlId="validationCustom05">
                    <Form.Label>First Password</Form.Label>
                    <Form.Control type="password" placeholder="Password" defaultValue={firstpassword} pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}"
                    onChange={(e) => {
                        setFirstpassword(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Password.
                    Must contain at least one number and one uppercase and lowercase letter, and at least 6 or more characters
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Col} md="3" controlId="validationCustom05">
                    <Form.Label>Second Password</Form.Label>
                    <Form.Control type="password" placeholder="Password" defaultValue={secondpassword} pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}"
                    onChange={(e) => {
                        setSecondpassword(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Password.
                    Must contain at least one number and one uppercase and lowercase letter, and at least 6 or more characters
                    </Form.Control.Feedback>
                </Form.Group>
                </Row>
                <Button type="submit">Save changes</Button>
                <Button type="reset">Reset</Button>
            </Form>
        </div>
    );
}
  
export default AdminUpdate;