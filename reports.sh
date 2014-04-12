echo "<pre>"
echo "<h1>Tor's Bleeding Edge nodes (guards and exits)</h1><br>"
echo "This page is updated every hour. Last update: "; date
echo "<br>"
echo "<h3 style="color:red">Bleeding Consensus Weight % - Guard nodes only:" && cat db/bleedingguard.db | awk '{print $3'} | python -c "import sys; print sum(float(l) for l in sys.stdin)" && echo "</h3>"
echo "<h3 style="color:red">Bleeding Consensus Weight % - Exit nodes only: " && cat db/bleedingexit.db | awk '{print $3'} | python -c "import sys; print sum(float(l) for l in sys.stdin)" && echo "</h3>"
echo "<h2>Here are the bleeding Guards:</h2>"
echo "Consensus Weight | Consensus Weight %     |  Details"
cat db/bleedingguard.db | sort -r -n
echo "<h3>Here are the bleeding Exits:</h3>"
echo " Consensus Weight | Consensus Weight %     |  Details"
cat db/bleedingexit.db | sort -r -n
echo "</pre><br>
Powered by: Stem (https://stem.torproject.org/)
Source Code
"

