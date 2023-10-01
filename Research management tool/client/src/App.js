import './App.css';
import React, { createContext, useReducer } from 'react';
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from './components/Login';
import StudentRegister from './components/StudentRegister';
import Header from './components/Header';
import Add from './components/Add'
import All from './components/All'
import Landing from './components/Landing'
import Update from './components/Update'
import UploadArea from './components/UploadArea';
import FilesList from './components/AllFiles';
import StudentUpdate from './components/StudentUpdate';
import StudentFilesList from './components/StudentFiles';
import StudentSubmissions from './components/StudentSubmission';
import StudentSubArea from './components/StudentSubArea';
import CreateGroup from './components/CreateGroup';
import StudentGroup from './components/ViewStudentGroup';
import RequestSupervisor from './components/RequestSupervisor';
import RequestCoSupervisor from './components/RequestCoSupervisor';
import AdminLog from './components/AdminLog';
import AdminHome from './components/AdminHome';
import AdminUpdate from './components/AdminUpdate';
import AllStudents from './components/StudentAll';
import AllStaff from './components/StaffAll';
import StaffUpdate from './components/StaffUpdate';
import StaffRegister from './components/StaffRegister';
import AllSubmissions from './components/SubmissionAll';
import CreateSubmission from './components/SubmissionCreate';
import UpdateSubmission from './components/SubmissionUpdate';
import UpdateStaffRole from './components/AddReArea';
import StaffHome from './components/StaffHome';
import StaffRequest from './components/StaffRequests';
import GroupChat from './components/GroupChat';
import AcceptedGroups from './components/AcceptedGroups';
import StaffGroupChat from './components/StaffGroupChat';
import AdminGroups from './components/AdminGroups';
import CreatePanelMembers from './components/CreatePanelMembers';
import CreatePanel from './components/CreatePanel';
import Panel from './components/Panels';
import StudentPanel from './components/StudentPanel';
import SubmittedFiles from './components/StudentSubmittedFiles';
import GroupSubmittedFiles from './components/StudentGroupSubmittedFiles';
import StaffPanel from './components/StaffPanel';
import StaffStudentSubmissionView from './components/StaffStudentSubmissionView';
import AssignedGroups from './components/AssignedGroups';
import PanelStudentSubmissionView from './components/PanelStudentSubmissionView';

//id, name, email, age, gender, nic, address, mobile, password

import { initialState, reducer } from '../src/reducer/UseReducer';

export const UserContext = createContext();

const Routing = () => {

  return(
    <Routes>
      <Route path='/log' element={<Login />} />
      <Route path='/sreg' element={<StudentRegister />} />
      <Route path='/supd' element={<StudentUpdate />} />
      <Route path='/allstudents' element={<AllStudents />} />
      <Route path='/studentfiles' element={<StudentFilesList />} />
      <Route path='/studentsubmissions' element={<StudentSubmissions />} />
      <Route path='/studentsubarea/:id/:name/:grpid/:panel' element={<StudentSubArea />} />
      <Route path='/creategroup' element={<CreateGroup />} />
      <Route path='/viewgroup' element={<StudentGroup />} />
      <Route path='/allstaff' element={<AllStaff />} />
      <Route path='/requestsupervisor' element={<RequestSupervisor />} />
      <Route path='/requestcosupervisor' element={<RequestCoSupervisor />} />
      <Route path='/staffreg' element={<StaffRegister />} />
      <Route path='/udatestaffrole/:id/:crole/:frole' element={<UpdateStaffRole />} />
      <Route path='/updatestaff/:id/:name/:email/:age/:gender/:nic/:address/:mobile/:password' element={<StaffUpdate />} />
      <Route path='/add' element={<Add />} />
      <Route path='/update' element={<Update />} />
      <Route path='/submit' element={<UploadArea />} />
      <Route path='/adminlog' element={<AdminLog />} />
      <Route path='/adminhome' element={<AdminHome />} />
      <Route path='/adminupdate' element={<AdminUpdate />} />
      <Route path='/allsubmissions' element={<AllSubmissions />} />
      <Route path='/createsubmission' element={<CreateSubmission />} />
      <Route exact path='/updatesubmission/:id/:name/:desc/:deadline' element={<UpdateSubmission />} />
      <Route path='/submissions' element={<FilesList />} />
      <Route path='/home' element={<All />} />
      <Route path='/stfhome' element={<StaffHome />} />
      <Route path='/staffrequests' element={<StaffRequest />} />
      <Route path='/grpcht' element={<GroupChat />} />
      <Route path='/acceptedgrps' element={<AcceptedGroups />} />
      <Route path='/stfgrpcht/:grpname' element={<StaffGroupChat />} />
      <Route path='/admingrp' element={<AdminGroups />} />
      <Route path='/panelmember' element={<CreatePanelMembers />} />
      <Route path='/createpanel' element={<CreatePanel />} />
      <Route path='/panel' element={<Panel />} />
      <Route path='/studentpanel' element={<StudentPanel />} />
      <Route path='/submittedfiles' element={<SubmittedFiles />} />
      <Route path='/staffpanel' element={<StaffPanel />} />
      <Route path='/groupsubmittedfiles/:name' element={<GroupSubmittedFiles />} />
      <Route path='/staffStudentsubmissionview/:name' element={<StaffStudentSubmissionView />} />
      <Route path='/panelstudentsubmissionview/:name' element={<PanelStudentSubmissionView />} />
      <Route path='/assignedgroups/:name' element={<AssignedGroups />} />
      <Route path='/' element={<Landing />} />
    </Routes>
  )
}
///:id/:name/:email/:age/:gender/:nic/:address/:mobile/:password
function App() {

  const [state, dispatch] = useReducer(reducer, initialState);

  return (
    <div>
      <Router>
        <UserContext.Provider value={{state, dispatch}}>
        <Header />
          <br/>
          <br/>
          <Routing />
        </UserContext.Provider>
      </Router>
    </div>
  );
}

export default App;
