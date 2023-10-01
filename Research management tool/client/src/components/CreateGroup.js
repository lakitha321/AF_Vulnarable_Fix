import React,{useState, useContext, useEffect} from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import { Button, Form, Row, Col } from "react-bootstrap";
import Card from "react-bootstrap/Card";
import { UserContext } from "../App";

function StaffRegister() {

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:1})

    const [validated, setValidated] = useState(false);
    const navigate = useNavigate();

    const [name, setName] = useState("");
    const member1 = localStorage.getItem("semail");
  
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

        let validate = false;

        const newGroup = {
            name,
            member1
        }

        const groupid = name;

        const updateSudentgroup = {
            groupid
        }

        axios.get(`http://localhost:8070/studentgroup/check/${name}`).then((res1)=>{
            validate = res1.data;
            if(validate){
                axios.post(`http://localhost:8070/studentgroup/create`, newGroup).then((res2)=>{
                    alert(res2.data.msg);
                    if(res2.data.status){
                      axios.put(`http://localhost:8070/student/updategroup/${member1}`, updateSudentgroup).then((res3)=>{
                        alert(res3.data.msg);
                        if(res3.data.status){
                            localStorage.setItem("sgroupid", groupid);
                            window.location.reload(false); 
                        }
                        }).catch((err)=>{
                            alert(err);
                        })
                    }
                }).catch((err)=>{
                    alert(err);
                })
            }
            else{
                alert("This group name is already existing!");
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    const [student, setStudent] = useState("");

    const studentgrpcheck = student.groupid;
    const member2check = student.member2;
    const member3check = student.member3;
    const member4check = student.member4;

    useEffect(() => {
        function getStudents(){
            axios.get(`http://localhost:8070/student/getgroup/${member1}`).then((res) => {
                setStudent(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStudents();
    }, []);
  
    return (
        <div className="container mt-5">
            <br/><br/>
            {studentgrpcheck == "Not defined" ? (
            <Card style={{ width: '48rem', margin:"auto", opacity:'90%' }}>
            <Card.Body>
                <Card.Title>Create a research group</Card.Title>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <p className="fs-3" style={{color:"red"}}>Attention!</p>
                        <p>Group name must be unique!</p>
                        <p>You can use only letters and numbers!</p>
                        <p>Group name must contain minimum 5 characters!</p><br/><br/>
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Control type="text" placeholder="Group name" pattern="[a-zA-Z0-9]{5,}"
                        onChange={(e) => {
                            setName(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Name.
                        </Form.Control.Feedback>
                    </Form.Group>
                    </Row>
                    <Button className="btn btn-success" type="submit" style={{opacity: "70%"}}>Create</Button>
                </Form>
                
            </Card.Body>
            </Card>
            ):(
                <>
                <br/><br/>
                <Card align="center" style={{ width: '48rem', margin:"auto", opacity:'90%' }}>
                <Card.Body>
                <br/>
                <Card.Title>{studentgrpcheck}</Card.Title>
                {member2check == "Not defined" ? (
                    <>
                    <br/>
                    <button type="button" class="btn btn-success" style={{opacity: "70%", width: '20rem'}} >
                    View group
                    </button>
                    <br/>
                    </>
                ):(
                    <></>
                )}
                </Card.Body>
                </Card>
                </>
            )}
            <br/><br/><br/>
        </div>
    );
}
  
export default StaffRegister;