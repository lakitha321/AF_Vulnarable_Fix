import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate, useParams } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";
import { UserContext } from "../App";


const User = () => {
    const { id, crole, frole } = useParams();

    const details = {
        id,
        crole,
        frole
    }

    return details;
}

function StaffUpdate() {
    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const data = User();

    const [validated, setValidated] = useState(false);
    const navigate = useNavigate();

    const [research, setresearch] = useState(data.research);
    var role = data.frole;
  
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

        const updateRole = {
            research,
            role
        }

        axios.put(`http://localhost:8070/staff/updaterole/${data.id}`, updateRole).then((res)=>{
            alert(res.data);
            navigate("/allstaff");
        }).catch((err)=>{
            alert(err);
        })
    }
  
    return (
        <div className="container mt-5">
            <br/><br/><br/><br/>
            <Card style={{ width: '68rem', margin:"auto" }}>
            <Card.Body>
                <Card.Title>Update Staff member role</Card.Title>
                <br/>
                <Card.Subtitle>Updating role from {data.crole} to {data.frole}</Card.Subtitle>
                <br/>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Label>Research Area</Form.Label>
                        <Form.Control type="text" placeholder="Reasearch area"
                        onChange={(e) => {
                            setresearch(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a research area.
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