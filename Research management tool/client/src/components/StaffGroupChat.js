import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import Card from "react-bootstrap/Card";
import { confirm } from "react-confirm-box";
import { useParams } from 'react-router-dom';
import {BrowserRouter as Router, Link} from 'react-router-dom';

import { UserContext } from "../App";

const User = () => {
    const { grpname } = useParams();

    const details = {
        grpname
    }

    return details;
}

export default function GroupChat(){

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:3});

    const data = User();

    const sgroup = data.grpname;
    const semail = localStorage.getItem("stfemail");

    const [msg, setMsg] = useState('');

    const [chatArr, setChat] = useState([]);
    
    useEffect(() => {
        function getChat(){
            axios.get(`http://localhost:8070/chat/${sgroup}`).then((res) => {
                setChat(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getChat();
    }, []);

    const sendMessage = () => {

        const sender = semail;
        const group = sgroup;
        const message = msg;
        const role = localStorage.getItem("stfrole");

        const newMessage = {
            sender,
            group,
            message,
            role
        }

        axios.post("http://localhost:8070/chat/add", newMessage).then(() => {
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    const deleteMessage = async (id) => {

        const result = await confirm("Do you want to delete this message?");
        if (result) {
            axios.delete(`http://localhost:8070/chat/delete/${id}`).then((res) => {
                window.location.reload(false);
            }).catch((err) => {
                alert(err);
            });
        }
    }

    return(
        <>
        <br/><br/>
        <div align='center'>
        <Card style={{ width: '80rem', backgroundColor: 'transparent', borderColor: 'white' }}>
        <br/>
            <div className="scroll-bg" align='center'>
                <div className="scroll-div">
                    <div className="scroll-object" style={{color:'white'}}>
                        {
                            chatArr.map((val, key) => {
                                return(
                                    <div style={{paddingTop: '10px'}}>
                                    {val.sender === semail ? (
                                        <div>
                                        <Card style={{ width: '25rem', backgroundColor: 'transparent', borderColor: 'white', borderRadius:'10px' }}>
                                            <table style={{width:'100%'}}>
                                                <tr>
                                                    <td align="right">
                                                    <Link to=''>
                                                    <a style={{color:'red', paddingRight: '10px'}}
                                                        onClick={() => {deleteMessage(val._id)}}
                                                    >
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-x-circle" viewBox="0 0 16 16">
                                                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                                                        <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
                                                        </svg>
                                                    </a>
                                                    </Link>
                                                    <p1 align='right' style={{fontSize:'10px', paddingRight: '10px'}}>{val.time}</p1>
                                                    </td>
                                                    <td>
                                                        
                                                    </td>
                                                </tr>
                                            </table>
                                            <p1 style={{paddingLeft: '10px', paddingTop: '10px', paddingRight: '10px'}}>{val.message}</p1>
                                        </Card>
                                        </div>
                                    ):(
                                        <>
                                        {val.role === "member" ? (
                                            <>
                                            <div align='left'>
                                            <Card style={{ width: '25rem', backgroundColor: 'white', color:'black', borderRadius:'10px' }}>
                                                <table style={{width:'100%'}}>
                                                    <tr>
                                                        <td align="right">
                                                        <p1 align='right' style={{fontSize:'10px', paddingRight: '10px'}}>{val.time}</p1>
                                                        </td>
                                                        <td align="left">
                                                        <p1 align='right' style={{fontSize:'10px', paddingLeft: '10px'}}>{val.sender}</p1>
                                                        </td>
                                                    </tr>
                                                </table>
                                                <p1 style={{paddingLeft: '10px', paddingTop: '10px', paddingRight: '10px'}}>{val.message}</p1>
                                            </Card>
                                            </div>
                                            </>
                                        ):(
                                            <>
                                            <div align='left'>
                                            <Card style={{ width: '25rem', backgroundColor: '#6495ED', color:'black', borderRadius:'10px' }}>
                                                <table style={{width:'100%'}}>
                                                    <tr>
                                                        <td align="right">
                                                        <p1 align='right' style={{fontSize:'10px', paddingRight: '10px'}}>{val.time}</p1>
                                                        </td>
                                                        <td align="left">
                                                        <p1 align='right' style={{fontSize:'10px', paddingLeft: '10px'}}>{val.sender}</p1>
                                                        </td>
                                                    </tr>
                                                </table>
                                                <p1 style={{paddingLeft: '10px', paddingTop: '10px', paddingRight: '10px'}}>{val.message}</p1>
                                            </Card>
                                            </div>
                                            </>
                                        )}
                                        
                                        </>
                                    )}
                                    </div>
                                )
                            })
                        }
                    </div>
                </div>
                <div style={{padding: '20px', paddingLeft: '50px'}}>
                <table className="mt-3">
                    <tr>
                        <td>
                        <input type="text" className="form-control" placeholder="Enter a message" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white', width:'68rem' }}
                        onChange = {(e) => {
                            setMsg(e.target.value);
                        }}
                        />
                        </td>

                        <td style={{paddingLeft: '20px'}}>
                        {msg ? (
                            <>
                            <button type="button" className="btn btn-success rounded-circle"
                            onClick={() => {sendMessage()}}
                            >
                            <svg xmlns="http://www.w3.org/2000/svg" width="23" height="23" fill="currentColor" class="bi bi-send" viewBox="0 0 16 16">
                                <path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11ZM6.636 10.07l2.761 4.338L14.13 2.576 6.636 10.07Zm6.787-8.201L1.591 6.602l4.339 2.76 7.494-7.493Z"/>
                            </svg>
                            </button>
                            </>
                        ):(
                            <></>
                        )}
                        </td>
                    </tr>
                </table>
                </div>
            </div>
        </Card>
        </div>
        </>
    )

}