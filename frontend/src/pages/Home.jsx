import { useEffect, useState } from "react";
import "./Home.css"; // Asegúrate de tener este archivo de estilo

function Home() {
  const [agfList, setAgfList] = useState([]); // Estado inicial es un array vacío

  useEffect(() => {
    fetch("http://138.4.21.21:8080/agfs")
      .then((res) => res.json())
      .then((data) => {
        // Verificamos si data.agfs es un array antes de actualizar el estado
        if (Array.isArray(data.agfs)) {
          setAgfList(data.agfs);
        } else {
          console.error("Error: La respuesta no contiene un array de AGFs.");
        }
      })
      .catch((err) => console.error("Error fetching AGFs:", err));
  }, []);

  return (
    <div className="home-container"> {/* Clase para el contenedor */}
      <h1>Controlador</h1>
      <p>AGFs registrados</p>

      <table>
        <thead>
          <tr>
            <th>gnbId (hex)</th>
          </tr>
        </thead>
        <tbody>
          {Array.isArray(agfList) && agfList.length > 0 ? (
            agfList.map((agf, idx) => (
              <tr key={idx}>
                <td>{agf.gnbId}</td>
              </tr>
            ))
          ) : (
            <tr className="no-data">
              <td colSpan="1">No hay datos recibidos aún.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default Home;