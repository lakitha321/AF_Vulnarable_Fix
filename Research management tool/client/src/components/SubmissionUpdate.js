import React,{useState, useContext} from "react";
import axios from "axios";
import { useNavigate, useParams } from 'react-router-dom';
import { Button, Form, InputGroup, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

const User = () => {
    const { id, name, desc, deadline } = useParams();

    const details = {
        id,
        name,
        desc,
        deadline
    }

    return details;
}

function UpdateSubmission() {

    // const nname = this.props.match.params.name;
    const data = User();

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [validated, setValidated] = useState(false);

    const [name, setName] = useState(data.name);
    const [desc, setDesc] = useState(data.desc);
    const [deadline, setDeadline] = useState(data.deadline);
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

        const updateSubmission = {
            name,
            desc,
            deadline,
            panel
        }

        axios.put(`http://localhost:8070/submission/update/${data.id}`, updateSubmission).then((res)=>{
            alert(res.data.status);
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
                <Card.Title>Update Submission</Card.Title>
                <Form noValidate className="mt-3" validated={validated} onSubmit={handleSubmit}>
                <Row className="mb-3">
                <Form.Group as={Row} md="6" controlId="validationCustom04">
                    <Form.Label>Name</Form.Label>
                    <Form.Control type="text" defaultValue={data.name} placeholder="Name"
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
                    <Form.Control type="text" defaultValue={data.desc} placeholder="Description"
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
                    <Form.Control type="text" defaultValue={data.deadline} placeholder="Deadline"
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
                <Button className="btn btn-primary" style={{opacity: "70%"}} type="submit">Save changes</Button>
            </Form>
            </Card.Body>
            </Card>
        </div>
    );
}
  
export default UpdateSubmission;