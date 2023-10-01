import React,{useState, useEffect, useContext } from "react";
import axios from "axios";
import { useNavigate, useParams } from 'react-router-dom';
import {Card, Modal} from "react-bootstrap";

import { UserContext } from "../App";

const User = () => {
    const { name } = useParams();

    const details = {
        name
    }

    return details;
}


export default function AssignedGroups(){

    const navigate = useNavigate();

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:3});

    const data = User();

    const [groupArr, setGroups] = useState([]);

    const [sgname, setSgname] = useState('');
    const [sgmember1, setSgmember1] = useState('');
    const [sgmember2, setSgmember2] = useState('');
    const [sgmember3, setSgmember3] = useState('');
    const [sgmember4, setSgmember4] = useState('');
    const [sgsupervisor, setSgsupervisor] = useState('');
    const [sgcosupervisor, setSgcosupervisor] = useState('');
    const [sgtopic, setSgtopic] = useState('');
    const [sgpanel, setSgpanel] = useState('');
    const [sgmarks, setSgmarks] = useState('');

    const [modalShow, setModalShow] = useState(false);

    useEffect(() => {
        function getAssignedGroups(){
            axios.get(`http://localhost:8070/studentgroup/getbypanel/${data.name}`).then((res) => {
                setGroups(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getAssignedGroups();
    }, []);

    function setGroupDetails(sgname, sgmember1, sgmember2, sgmember3, sgmember4, sgsupervisor, sgcosupervisor, sgtopic, sgpanel, sgmarks){

        setSgname(sgname);
        setSgmember1(sgmember1);
        setSgmember2(sgmember2);
        setSgmember3(sgmember3);
        setSgmember4(sgmember4);
        setSgsupervisor(sgsupervisor);
        setSgcosupervisor(sgcosupervisor);
        setSgtopic(sgtopic);
        setSgpanel(sgpanel);
        setSgmarks(sgmarks);

        setModalShow(true);
    }

    function navigateSubmission(id){
        navigate(`/panelstudentsubmissionview/${id}`);
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
                Group name : {sgname}
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <h5>Topic : {sgtopic}</h5>
                <p>Member 1 : {sgmember1}</p>
                <p>Member 2 : {sgmember2}</p>
                <p>Member 3 : {sgmember3}</p>
                <p>Member 4 : {sgmember4}</p>
                <h5>Supervisor : {sgsupervisor}</h5>
                <h5>Co-supervisor : {sgcosupervisor}</h5>
                <h5>Panel : {sgpanel}</h5>
                <p>Marks : {sgmarks}</p>
            </Modal.Body>
          </Modal>
        );
    }

    return(
        <div className="container my-5">
           <div className="row">
                <MyVerticallyCenteredModal
                    show={modalShow}
                    onHide={() => setModalShow(false)}
                />
                {
                    groupArr.map((val, key) => {
                        return(
                            <div className="col-12" align="center" key={val._id}>
                                <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                <Card.Body>
                                <Card.Subtitle align="left" style={{ color: 'white'}}>{key + 1}</Card.Subtitle>
                                    <Card.Title align="center" style={{ color: 'white'}}>Group = {val.name}</Card.Title>
                                    <Card.Subtitle align="center" style={{color:"white"}}>Topic = {val.topic}</Card.Subtitle>
                                    <br/>
                                    <button type="button" class="btn btn-primary" style={{width: '15rem'}} 
                                    onClick={() => setGroupDetails(val.name, val.member1, val.member2, val.member3, val.member4, val.supervisor, val.cosupervisor, val.topic, val.panel, val.marks)}>
                                        View group details
                                    </button>
                                    $nbsp;
                                    <button type="button" class="btn btn-light" style={{width: '15rem'}} 
                                    onClick={() => navigateSubmission(val.name)}>
                                        View group submissions
                                    </button>
                                    <br/>  
                                </Card.Body>
                                </Card><br/><br/>
                            </div>
                        )
                    })
                }
            </div>
        </div>
    )

}