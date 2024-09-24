import React, { useState, useEffect} from 'react'

function App() {
  const [data, setData] = useState(null)
  useEffect(() => {
    fetch("/message").then(res => res.json()).then(data => {
      setData(data.message)
      console.log(data)
    })
  
  }, [])
  
  return (
    <div>
      App
    </div>
  )
}

export default App
