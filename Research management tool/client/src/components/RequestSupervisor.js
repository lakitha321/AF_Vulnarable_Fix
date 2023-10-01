import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";
import {Card, Modal} from "react-bootstrap";

import { UserContext } from "../App";

export default function AllStaff(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:1});

    const grpID = localStorage.getItem("sgroupid");

    const [staffArr, setStaff] = useState([]);
    const [requests, setRequest] = useState([]);

    const [Staff, setStf] = useState([]);

    const [modalShow, setModalShow] = useState(false);
    

    useEffect(() => {
        function getStaff(){
            axios.get("http://localhost:8070/staff/getsup").then((res) => {
                setStaff(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        function getRequest(){
            axios.get(`http://localhost:8070/request/${grpID}`).then((res) => {
                setRequest(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStaff();
        getRequest();
    }, []);

    const saveRequest = async() => {

        var topic = document.getElementById("topic").value;
        
        // window.localStorage.setItem('topic', topic);

        const grp = grpID;

        const newRequest = {
            grp,
            Staff,
            topic
        }

        axios.post('http://localhost:8070/request/add', newRequest).then((res) => {
            alert(res.data);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    const deleteRequest = async(id) => {
        axios.delete(`http://localhost:8070/request/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    function setData(s){

        setStf(s);
    
        setModalShow(true);
    }
    
    function MyVerticallyCenteredModal(props) {
        return (
          <Modal
            {...props}
            size="lg"
            aria-labelledby="contained-modal-title-vcenter"
            centered
            align='center'
          >
            <Modal.Header closeButton>
              <Modal.Title>
                Enter your research topic
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
            <form class="d-flex" onSubmit={() => saveRequest()}>
                <input class="form-control me-2" id="topic" type="search" placeholder="Enter your research topic" aria-label="Search" required />
                <button class="btn btn-success" type="submit">
                    Request
                </button>
            </form>
            </Modal.Body>
          </Modal>
        );
    }

    return(
        <div className="container">
            <br/><br/><br/>
            <MyVerticallyCenteredModal
                show={modalShow}
                onHide={() => setModalShow(false)}
            />
            <div align='center'>
                {
                    requests.map((val, key) => {
                        return(
                            <>
                            <div className="col-12" align="center" key={val._id}>
                                <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                <Card.Body>
                                <Card.Subtitle align="right">
                                    <button type="button" class="btn btn-danger" style={{width: '3rem'}} onClick={() => {deleteRequest(val._id)}}>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                                    <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8 2.146 2.854Z"/>
                                    </svg>
                                    </button>
                                </Card.Subtitle>
                                    <Card.Title align="center" style={{ color: 'white'}}>Requested on : {val.time}</Card.Title>
                                    <Card.Text align="center" style={{ color: 'white'}}>Group : {val.grp}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>Topic choosen : {val.topic}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>Requested Supervisor : {val.Staff}</Card.Text>
                                    {val.status === "Pending..." ? (
                                        <>
                                            <Card.Subtitle align="center" style={{ color: 'yellow'}}>Request is {val.status}</Card.Subtitle>
                                        </>
                                    ):(
                                        <>
                                            {val.status === "Rejected" ? (
                                                <>
                                                    <Card.Subtitle align="center" style={{ color: 'red'}}>Request {val.status}</Card.Subtitle>
                                                </>
                                            ):(
                                                <>
                                                    <Card.Subtitle align="center" style={{ color: 'lime'}}>Request {val.status}</Card.Subtitle>
                                                </>
                                            )}
                                        </>
                                    )}
                                    {val.feedback ? (
                                        <>
                                            <Card.Text align="center" style={{ color: 'white'}}>Feedback : {val.feedback}</Card.Text>
                                        </>
                                    ):(
                                        <>
                                        </>
                                    )}
                                    {/* <Card.Text align="center" style={{ color: 'white'}}>{val.feedback}</Card.Text> */}
                                </Card.Body>
                                </Card><br/><br/>
                            </div>
                            </>
                        )
                    })
                }
            </div>
            <br/><br/>
            <p className="fs-2" style={{ color: 'white'}}>&nbsp;&nbsp;&nbsp;Supervisors</p>
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                   <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>R area</th>
                    <th></th>
                   </tr>
               </thead>
               <tbody>
                   {
                       staffArr.map((val, key) => {
                            return(
                                <>
                                <tr key={val._id}>
                                    <td>{val.name}</td>
                                    <td>{val.email}</td>
                                    <td>{val.role}</td>
                                    <td>{val.research}</td>
                                    <td align="right">
                                    <button class="btn btn-success" type="submit" onClick={() => setData(val.email)}>
                                        Request
                                    </button>
                                    </td>
                                </tr>
                                
                                </>
                            )
                       })
                   }
               </tbody>
           </table>
           
        </div>
    )

}