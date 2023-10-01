import React,{useState, useEffect, useContext } from "react";
import axios from "axios";
import Card from "react-bootstrap/Card";
import { useNavigate } from 'react-router-dom';

import { UserContext } from "../App";

export default function StudentPanels(){

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:3});

    const navigate = useNavigate();

    const [panelArr, setPanel] = useState([]);

    const myEmail = localStorage.getItem("stfemail");

    useEffect(() => {
        function getPanel(){
            axios.get("http://localhost:8070/panel/").then((res) => {
                setPanel(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getPanel();
    }, []);

    function nav(name){
        navigate(`/assignedgroups/${name}`);
    }

    return(
        <div className="container my-5" align='center'>
            <br/><br/><br/>
           <div className="row">
                {
                    panelArr.map((val, key) => {
                        return(
                            <>
                            {(val.member1 === myEmail || val.member2 === myEmail || val.member3 === myEmail || val.member4 === myEmail) ? (
                                <>
                                <div className="col-12" align="center" key={val._id}>
                                    <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                        <br/>
                                    <Card.Body>
                                        <Card.Title align="center" style={{ color: 'white'}}>{val.name}</Card.Title>
                                        <br/>
                                        <Card.Text align="center" style={{ color: 'white'}}>{val.member1}</Card.Text>
                                        <Card.Text align="center" style={{ color: 'white'}}>{val.member2}</Card.Text>
                                        <Card.Text align="center" style={{ color: 'white'}}>{val.member3}</Card.Text>
                                        <Card.Text align="center" style={{ color: 'white'}}>{val.member4}</Card.Text>
                                        <br/>
                                        <button type="button" class="btn btn-primary" style={{width: '15rem'}} onClick={() => {nav(val.name)}} >
                                            Check assigned groups
                                        </button>
                                        <br/><br/>
                                    </Card.Body>
                                    </Card><br/><br/>
                                </div>
                                </>
                            ):(
                                <>
                                </>
                            )}
                            </>
                        )
                    })
                }
            </div>
        </div>
    )

}