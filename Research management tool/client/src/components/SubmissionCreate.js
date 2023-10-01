import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, InputGroup, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

function CreateSubmission() {

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [validated, setValidated] = useState(false);

    const [name, setName] = useState();
    const [desc, setDesc] = useState();
    const [deadline, setDeadline] = useState();
    const [panel, setPanel] = useState("NO");
  
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

    const sendData = () => {

        const newSubmission = {
            name,
            desc,
            deadline,
            panel
        }

        axios.post("http://localhost:8070/submission/add", newSubmission).then((res)=>{
            alert(res.data);
            navigate("/allsubmissions");
        }).catch((err)=>{
            alert(err);
        })
    }

    return (
        <div className="container mt-5">
            <br/><br/>
            <Card style={{ width: '38rem', margin:"auto" }}>
            <Card.Body>
                <Card.Title>Create a new Submission</Card.Title>
                <Form noValidate className="mt-3" validated={validated} onSubmit={handleSubmit}>
                <Row className="mb-3">
                <Form.Group as={Row} md="6" controlId="validationCustom04">
                    <Form.Label>Name</Form.Label>
                    <Form.Control type="text" placeholder="Name"
                    onChange={(e) => {
                        setName(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please enter the submission name
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Row} md="3" controlId="validationCustom05">
                    <Form.Label>Description</Form.Label>
                    <Form.Control type="text" placeholder="Description"
                    onChange={(e) => {
                        setDesc(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please enter a description
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Row} md="3" controlId="validationCustom05">
                    <Form.Label>Deadline</Form.Label>
                    <Form.Control type="text" placeholder="Deadline"
                    onChange={(e) => {
                        setDeadline(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please enter a deadline
                    </Form.Control.Feedback>
                </Form.Group>
                <Form.Group as={Row} md="2" controlId="validationCustom04">
                    <Form.Label className='mt-3'>Panel access</Form.Label>
                    <select id="inputState" class="form-select"
                    onChange={(e) => {
                        setPanel(e.target.value);
                    }}
                    required>
                    <option selected>NO</option>
                    <option>YES</option>
                    </select>
                    <Form.Control.Feedback type="invalid">
                    Please provide a selection.
                    </Form.Control.Feedback>
                </Form.Group>
                </Row>
                <Button className="btn btn-success" style={{opacity: "70%"}} type="submit">Add</Button>
            </Form>
            </Card.Body>
            </Card>
        </div>
    );
}
  
export default CreateSubmission;