import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

export default function Panel(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [staffArr, setStaff] = useState([]);

    const [name, setName] = useState('');
    const [member1, setMember1] = useState('');
    const [member2, setMember2] = useState('');
    const [member3, setMember3] = useState('');
    const [member4, setMember4] = useState('');

    useEffect(() => {
        function getStaff(){
            axios.get("http://localhost:8070/staff/").then((res) => {
                setStaff(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStaff();
    }, []);

    const addToPanel = (email) => {

        axios.put(`http://localhost:8070/staff/addtopanel/${email}`).then(() => {
        }).catch((err) => {
            alert(err);
        });
    }

    const removeFromPanel = async (email) => {

        axios.put(`http://localhost:8070/staff/removefrompanel/${email}`).then(() => {
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    const createNewPanel = () => {

        const newPanel = {
            name,
            member1,
            member2,
            member3,
            member4
        }

        axios.post('http://localhost:8070/panel/', newPanel).then((res) => {

            // alert("newPanel.member1");

            // axios.put(`http://localhost:8070/staff/addtopanel/${member1}`).then(() => {
            // }).catch((err) => {
            //     alert(err);
            // });
            
        }).catch((err) => {
            alert(err);
        });
    }

    function selectMembers(member){

        if(member1 === ''){
            setMember1(member);
        }
        else if(member2 === ''){
            setMember2(member);
        }
        else if(member3 === ''){
            setMember3(member);
        }
        else if(member4 === ''){
            setMember4(member);
        }
        else{
            alert("Panel is full!")
        }
    }

    return(
        <>
        <div className="container">
            <br/><br/><br/><br/>
            <div className="container" style={{backgroundColor:'white'}}>
                <br/>
                <h4>Create a new panel</h4>
                <br/>
                <form align='center'>
                    <input class="form-control" type="text" placeholder="Panel name" onChange={(e) => setName(e.target.value)} required />
                    <br/>
                    <p>{member1}</p>
                    <p>{member2}</p>
                    <p>{member3}</p>
                    <p>{member4}</p>
                    <br/>
                    {(name && member1 && member2 && member3 && member4) ? (
                        <>
                        <button class="btn btn-primary" type="submit" onClick={() => {createNewPanel()}}>
                            Done
                        </button>
                        </>
                    ):(
                        <>
                        <h5>Select four panel members</h5>
                        </>
                    )}
                    
                </form>
                <br/><br/>
            </div>
            <br/>&nbsp;&nbsp;
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                   <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Panel</th>
                    <th>Operation</th>
                   </tr>
               </thead>
               <tbody>
                   {
                       staffArr.map((val, key) => {
                           if(val.panel === "YES"){

                           }
                           else{
                            return(
                                <>
                                    {(member1 === val.email || member2 === val.email || member3 === val.email || member4 === val.email) ? (
                                        <>
                                        
                                        </>
                                    ):(
                                        <>
                                            <tr key={val._id}>
                                                <td>{val.name}</td>
                                                <td>{val.email}</td>
                                                <td>{val.role}</td>
                                                <td>{val.panel}</td>
                                                <td align="right" style={{width:'18px'}}>
                                                    <button type="button" class="btn btn-success" onClick={() => selectMembers(val.email)}>
                                                        Select
                                                    </button>
                                                </td>
                                            </tr>
                                        </>
                                    )}
                                
                                </>
                            )}
                       })
                   }
               </tbody>
           </table>
        </div>
        </>
    )

}