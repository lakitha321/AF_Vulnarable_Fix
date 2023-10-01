import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

const deleteStudent = async (id) => {
    const result1 = await confirm("Are you sure do you want to delete?");
    if (result1) {
       axios.delete(`http://localhost:8070/student/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.assign("/allstudents");
        }).catch((err) => {
            alert(err);
        }); 
    }

}

export default function AllStudents(){

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [studentArr, setStudent] = useState([]);

    const [search, setSearch] = useState('');

    useEffect(() => {
        function getStudents(){
            axios.get("http://localhost:8070/student/").then((res) => {
                setStudent(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStudents();
    }, []);
    

    return(
        <div className="container my-5">
            <div align='right'>
            <input type="text" class="form-control" placeholder="Search by name" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white', width:'20rem' }} onChange={(e) => {setSearch(e.target.value)}}/>
            </div>
            <br/>
           <table className="table table-hover" style={{ color: 'white'}}>
               <thead>
                   <tr>
                    <th>#</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Age</th>
                    <th>Gender</th>
                    <th>NIC</th>
                    <th>Address</th>
                    <th>Mobile</th>
                    <th>GroupID</th>
                    <th ></th>
                   </tr>
               </thead>
               <tbody>
                   {
                       studentArr.map((val, key) => {
                           let x = val.name;
                            return(
                                <>
                                {search ? (
                                    <>
                                    {x.includes(search) ? (
                                        <>
                                        <tr key={val._id}>
                                            <td>{key + 1}</td>
                                            <td>{val.name}</td>
                                            <td>{val.email}</td>
                                            <td>{val.age}</td>
                                            <td>{val.gender}</td>
                                            <td>{val.nic}</td>
                                            <td>{val.address}</td>
                                            <td>{val.mobile}</td>
                                            <td>{val.groupid}</td>
                                            <td align="right">
                                                <div class="btn-group" role="group" aria-label="Basic outlined example">
                                                    <button type="button" class="btn btn-danger" style={{opacity: "70%"}} onClick={() => deleteStudent(val._id)}>
                                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                                    <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                                    </svg>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        </>
                                    ):(
                                        <>
                                        </>
                                    )}
                                    </>
                                ):(
                                    <>
                                    <tr key={val._id}>
                                        <td>{key + 1}</td>
                                        <td>{val.name}</td>
                                        <td>{val.email}</td>
                                        <td>{val.age}</td>
                                        <td>{val.gender}</td>
                                        <td>{val.nic}</td>
                                        <td>{val.address}</td>
                                        <td>{val.mobile}</td>
                                        <td>{val.groupid}</td>
                                        <td align="right">
                                            <div class="btn-group" role="group" aria-label="Basic outlined example">
                                                <button type="button" class="btn btn-danger" style={{opacity: "70%"}} onClick={() => deleteStudent(val._id)}>
                                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                                <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                                </svg>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    </>
                                )}
                                
                                </>
                            )
                       })
                   }
               </tbody>
           </table>
        </div>
    )

}