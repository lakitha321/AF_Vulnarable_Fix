import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from './Login';
import Header from './Header';
import Add from './Add'
import All from './All'
import Update from './Update'
import UploadArea from './UploadArea';
import FilesList from './StudentSubmissions';

function AppContainer() {
  return (
    <div>
    <Header />
    <Routes>
        <Route path='/add' element={<Add />} />
        <Route path='/update' element={<Update />} />
        <Route path='/submit' element={<UploadArea />} />
        <Route path='/submissions' element={<FilesList />} />
        <Route path='/all' element={<All />} />
    </Routes>
    </div>
  );
}

export default AppContainer;
