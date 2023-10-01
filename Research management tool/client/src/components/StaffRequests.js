import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";
import {Modal} from "react-bootstrap";

import { UserContext } from "../App";

export default function Requests(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:3})

    const [requestArr, setRequest] = useState([]);

    const [id, setId] = useState('');
    const [status, setStatus] = useState('');
    const stfemail = localStorage.getItem("stfemail");
    const role = localStorage.getItem("stfrole");

    const [modalShow, setModalShow] = useState(false);
    

    useEffect(() => {
        function getRequests(){
            axios.get(`http://localhost:8070/request/get/${stfemail}`).then((res) => {
                setRequest(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getRequests();
    }, []);

    const passValues = (id, status) => {

        setId(id);
        setStatus(status);

        setModalShow(true);
    }

    const updateStatusR = async () => {

        var feedback = document.getElementById("fdbk").value;


        const updateRequest = {
            status,
            feedback
        }

        axios.put(`http://localhost:8070/request/updateStatus/${id}`, updateRequest).then((res) => {
            alert(res.data.msg);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        })

    }

    const updateStatusA = async (id, status, name, topic) => {

        const feedback = '';

        const updateRequest = {
            status,
            feedback
        }

        const supervisor = stfemail;
        const cosupervisor = stfemail;

        const updatesGroup = {
            supervisor,
            topic
        }

        const updatesGroupCo = {
            cosupervisor,
        }

        axios.put(`http://localhost:8070/request/updateStatus/${id}`, updateRequest).then((res) => {
            alert(res.data.msg);

            if(res.data.status == true){
                if(role === "Co-supervisor"){
                    axios.put(`http://localhost:8070/studentgroup/updateCoSupervisor/${name}`, updatesGroupCo).then((res) => {
                        alert(res.data.msg);
                        window.location.reload(false);
                    }).catch((err) => {
                        alert(err);
                    })
                }
                else if(role === "Supervisor"){
                    axios.put(`http://localhost:8070/studentgroup/updateSupervisorAndTopic/${name}`, updatesGroup).then((res) => {
                        alert(res.data.msg);
                        window.location.reload(false);
                    }).catch((err) => {
                        alert(err);
                    })
                }
                
            }
        }).catch((err) => {
            alert(err);
        });

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
                Please provide a feedback!
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
            <form class="d-flex" onSubmit={() => updateStatusR()}>
                <input class="form-control me-2" id="fdbk" type="search" placeholder="Enter a feedback" aria-label="Search" required />
                <button class="btn btn-danger" type="submit">
                    Done
                </button>
            </form>
            </Modal.Body>
          </Modal>
        );
    }

    return(
        <div className="container">
            <MyVerticallyCenteredModal
                show={modalShow}
                onHide={() => setModalShow(false)}
            />
            <br/><br/>&nbsp;&nbsp;
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                   <th>Group</th>
                    <th>Topic</th>
                    <th>Date</th>
                    <th>Status</th>
                    <th>Feedback</th>
                    <th></th>
                   </tr>
               </thead>
               <tbody>
                   {
                       requestArr.map((val, key) => {
                            return(
                                <tr key={val._id}>
                                    <td>{val.grp}</td>
                                    <td>{val.topic}</td>
                                    <td>{val.time}</td>
                                    <td>{val.status}</td>
                                    <td>{val.feedback}</td>
                                    <td align="right" style={{width:'18px'}}>
                                        {val.status === "Pending..." ? (

                                            <div class="btn-group" role="group" aria-label="Basic mixed styles example">
                                            <button type="button" class="btn btn-danger" onClick={() => passValues(val._id, "Rejected")}>
                                                Reject
                                            </button>
                                            <button type="button" class="btn btn-success" onClick={() => updateStatusA(val._id, "Accepted", val.grp, val.topic)}>
                                                Accept
                                            </button>
                                            </div>

                                        ):(
                                            <></>
                                        )}
                                    </td>
                                </tr>
                            )
                       })
                   }
               </tbody>
           </table>
        </div>
    )

}