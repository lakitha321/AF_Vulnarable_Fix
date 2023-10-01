import React,{useState, useContext} from "react";
import axios from "axios";
import { Button, Form, InputGroup, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

function AdminLog() {


    const {state, dispatch} = useContext(UserContext);

    const [validated, setValidated] = useState(false);
    const [secondpassword, setPass] = useState();

    const aemail = localStorage.getItem("aemail");
  
    const handleSubmit = (event) => {
      const form = event.currentTarget;
      if(form.checkValidity()==true){
        event.preventDefault();
        event.stopPropagation();
        adminNav2();
        
      }
      else{
        if (form.checkValidity() == false) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        setValidated(true); 
      }
      
    };

    const adminNav2 = () => {

        const validateAdmin2 = {
            secondpassword
        }

        axios.post(`http://localhost:8070/admin/secondlog/${aemail}`, validateAdmin2).then((res)=>{
            if(res.data.status){

                localStorage.setItem("aid", res.data.Admins._id);
                localStorage.setItem("aname", res.data.Admins.name);
                localStorage.setItem("anic", res.data.Admins.nic);
                localStorage.setItem("amobile", res.data.Admins.mobile);
                localStorage.setItem("afirstpassword", res.data.Admins.firstpassword);
                localStorage.setItem("asecondpassword", res.data.Admins.secondpassword);

                alert('Step 2 authenticated');

                dispatch({type:"USER", payload:2})
                window.location.assign('/adminhome');
            }
            else{
                alert('Invalid username or password')
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    return (
        <div className="container mt-5">
            <br/><br/><br/>
            <Card style={{backgroundColor : 'transparent', width: '38rem', margin:"auto" }}>
            <Card.Body align="center">
            <Card.Title style={{color : 'white'}}>Admin verification</Card.Title><br/>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="3" controlId="validationCustom05">
                        <Form.Control type="password" placeholder="Password" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white' }}
                        onChange={(e) => {
                            setPass(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please enter your Password
                        </Form.Control.Feedback>
                    </Form.Group>
                    </Row>
                    <br/>
                    <Button type="submit">Sign in</Button>
                </Form>
            </Card.Body>
            </Card>
        </div>
    );
}
  
export default AdminLog;