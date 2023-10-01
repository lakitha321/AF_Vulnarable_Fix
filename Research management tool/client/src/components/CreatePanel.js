import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

const deleteStaff = async (id) => {
    const result1 = await confirm("Are you sure do you want to delete this Staff member?");
    if (result1) {
        console.log(id);
        axios.delete(`http://localhost:8070/staff/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.assign("/allstaff");
        }).catch((err) => {
            alert(err);
        });
    }
    
}

export default function AllStaff(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [staffArr, setStaff] = useState([]);

    const [panelName, setPanelName] = useState('');

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

    function passValues(id, name, email, age, gender, nic, address, mobile, password){
        navigate(`/updatestaff/${id}/${name}/${email}/${age}/${gender}/${nic}/${address}/${mobile}/${password}`);
        ///${id}/${name}/${email}/${age}/${gender}/${nic}/${address}/${mobile}/${password}/${role}/${research}
    }

    function addPanel(){

    }
    

    return(
        <>
            <br/><br/>&nbsp;&nbsp;
            <form class="d-flex" onSubmit={() => addPanel()}>
                <input class="form-control me-2" type="search" placeholder="Enter a feedback" aria-label="Search" onChange={() => {setPanelName()}} required />
                <button class="btn btn-danger" type="submit">
                    Create
                </button>
            </form>
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <tbody>
                   {
                       staffArr.map((val, key) => {
                            return(
                                <tr key={val._id}>
                                    <td>{val.name}</td>
                                    <td>{val.email}</td>
                                    <td>{val.age}</td>
                                    <td>{val.gender}</td>
                                    <td>{val.nic}</td>
                                    <td>{val.address}</td>
                                    <td>{val.mobile}</td>
                                    <td>{val.password}</td>
                                    <td>{val.role}</td>
                                    <td>{val.research}</td>
                                    <td align="right" style={{width:'18px'}}>
                                    </td>
                                </tr>
                            )
                       })
                   }
               </tbody>
           </table>
        </>
    )

}