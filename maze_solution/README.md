This is just *a* solution, and definitely not the best one.
This solution uses a custom mutator to ensure inputs always only consist of combinations of "wasd".
It also uses a custom feedback that maps newly traversed maze path by looking for '.' characters.

Things that it does not do that it could:
- Use a scheduler to prioritize inputs that go farter in the maze
- Use a minimization step to simplify input items that waste characters 

