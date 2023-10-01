import React,{useState, useEffect, useContext } from "react";
import axios from "axios";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

export default function Panels(){

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [panelArr, setPanel] = useState([]);

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

    const deletePanel = (id) => {
        axios.delete(`http://localhost:8070/panel/${id}`).then((res) => {
            alert(res.data);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    return(
        <div className="container my-5" align='center'>
            <br/>
            <a href="/panelmember">
                <button type="button" class="btn btn-success" style={{width: '10rem'}}>
                    Create
                </button>
            </a>
            <br/><br/><br/><br/>
           <div className="row">
                {
                    panelArr.map((val, key) => {
                        return(
                            <div className="col-12" align="center" key={val._id}>
                                <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                <Card.Body>
                                <div align="right">
                                <button type="button" class="btn btn-danger" style={{width: '3rem'}} onClick={() => {deletePanel(val._id)}} >
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                </svg>
                                </button>
                                </div>
                                    <Card.Title align="center" style={{ color: 'white'}}>{val.name}</Card.Title>
                                    <Card.Text align="center" style={{ color: 'white'}}>{val.member1}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>{val.member2}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>{val.member3}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>{val.member4}</Card.Text>
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